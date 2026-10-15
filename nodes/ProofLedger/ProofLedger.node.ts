import { createHash } from 'crypto';
import type {
	IDataObject,
	IExecuteFunctions,
	INodeExecutionData,
	INodeProperties,
	INodeType,
	INodeTypeDescription,
	JsonObject,
} from 'n8n-workflow';
import { NodeApiError, NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';

import { proofLedgerApiRequest } from './transport';

const SHA256_RE = /^[a-fA-F0-9]{64}$/;
const BATCH_SIZE = 100;

const proofOperations: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['proof'] } },
		options: [
			{
				name: 'Create From File',
				value: 'createFromFile',
				action: 'Hash a binary file in n8n and anchor the hash',
				description:
					'Compute the SHA-256 of a binary field locally and submit only the hash. The file never leaves n8n.',
			},
			{
				name: 'Create From Hash',
				value: 'create',
				action: 'Anchor a SHA-256 hash',
				description: 'Submit a 64-character SHA-256 hex digest for anchoring on Polygon',
			},
			{
				name: 'Create Many',
				value: 'createMany',
				action: 'Anchor every incoming hash in batches of 100',
				description: 'One batch call per 100 items, checked first and written together',
			},
			{
				name: 'Get',
				value: 'get',
				action: 'Get a proof by ID',
				description: 'Status, Polygon transaction and certificate links of one proof',
			},
			{
				name: 'Get Bundle',
				value: 'getBundle',
				action: 'Get a proof bundle',
				description:
					'Everything needed to verify the proof without ProofLedger, in the verify-proof file format',
			},
			{
				name: 'Get by External ID',
				value: 'getByExternalId',
				action: 'Get a proof by your own record ID',
				description: 'Look a proof up by the external_id you sent when creating it',
			},
			{
				name: 'Get Many',
				value: 'getMany',
				action: 'List proofs',
				description: 'Newest first, optionally only those anchored since a time',
			},
			{
				name: 'Verify',
				value: 'verify',
				action: 'Verify a hash',
				description: 'Check whether a SHA-256 hash has a proof (the public verify endpoint)',
			},
		],
		default: 'create',
	},
];

const webhookOperations: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['webhook'] } },
		options: [
			{
				name: 'Create',
				value: 'create',
				action: 'Register a webhook endpoint',
				description:
					'Register a public https URL to receive signed events. Prefer the ProofLedger Trigger node, which does this for you.',
			},
			{
				name: 'Delete',
				value: 'delete',
				action: 'Remove a webhook endpoint',
			},
			{
				name: 'Get Many',
				value: 'getAll',
				action: 'List webhook endpoints',
				description: 'Secrets are never shown',
			},
			{
				name: 'Test',
				value: 'test',
				action: 'Send a signed test event now',
			},
		],
		default: 'getAll',
	},
];

const accountOperations: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: ['account'] } },
		options: [
			{
				name: 'Get Branding',
				value: 'getBranding',
				action: 'Get the certificate branding line',
				description:
					'Whether partner branding is approved and the exact line shown on certificates',
			},
		],
		default: 'getBranding',
	},
];

const additionalProofFields: INodeProperties = {
	displayName: 'Additional Fields',
	name: 'additionalFields',
	type: 'collection',
	placeholder: 'Add Field',
	default: {},
	displayOptions: {
		show: { resource: ['proof'], operation: ['create', 'createFromFile', 'createMany'] },
	},
	options: [
		{
			displayName: 'External ID',
			name: 'externalId',
			type: 'string',
			default: '',
			description:
				'Your own record ID (up to 128 characters). Sending the same external ID again returns the existing proof instead of creating another.',
		},
		{
			displayName: 'Filename',
			name: 'filename',
			type: 'string',
			default: '',
			description:
				'Shown on the certificate. For Create From File it defaults to the binary field’s file name.',
		},
	],
};

const proofFields: INodeProperties[] = [
	{
		displayName: 'SHA-256 Hash',
		name: 'sha256',
		type: 'string',
		default: '',
		required: true,
		placeholder: 'e.g. a1b2c3…  (64 hex characters)',
		description: 'Hash the file yourself; only the hash is sent',
		displayOptions: { show: { resource: ['proof'], operation: ['create', 'createMany', 'verify'] } },
	},
	{
		displayName: 'Input Binary Field',
		name: 'binaryPropertyName',
		type: 'string',
		default: 'data',
		required: true,
		description: 'Name of the binary field on the incoming item that holds the file',
		displayOptions: { show: { resource: ['proof'], operation: ['createFromFile'] } },
	},
	additionalProofFields,
	{
		displayName: 'Proof ID',
		name: 'proofId',
		type: 'string',
		default: '',
		required: true,
		description: 'The numeric ID returned when the proof was created',
		displayOptions: { show: { resource: ['proof'], operation: ['get', 'getBundle'] } },
	},
	{
		displayName: 'External ID',
		name: 'externalId',
		type: 'string',
		default: '',
		required: true,
		description: 'The external_id you sent when creating the proof',
		displayOptions: { show: { resource: ['proof'], operation: ['getByExternalId'] } },
	},
	{
		displayName: 'Return All',
		name: 'returnAll',
		type: 'boolean',
		default: false,
		description: 'Whether to return all results or only up to a given limit',
		displayOptions: { show: { resource: ['proof'], operation: ['getMany'] } },
	},
	{
		displayName: 'Limit',
		name: 'limit',
		type: 'number',
		typeOptions: { minValue: 1 },
		default: 50,
		description: 'Max number of results to return',
		displayOptions: { show: { resource: ['proof'], operation: ['getMany'], returnAll: [false] } },
	},
	{
		displayName: 'Filters',
		name: 'filters',
		type: 'collection',
		placeholder: 'Add Filter',
		default: {},
		displayOptions: { show: { resource: ['proof'], operation: ['getMany'] } },
		options: [
			{
				displayName: 'Anchored Since',
				name: 'anchoredSince',
				type: 'dateTime',
				default: '',
				description: 'Only proofs whose Polygon anchor landed at or after this time',
			},
		],
	},
];

const webhookFields: INodeProperties[] = [
	{
		displayName: 'URL',
		name: 'url',
		type: 'string',
		default: '',
		required: true,
		placeholder: 'https://example.com/proofledger/events',
		description: 'A public https address. Private, loopback and plain http addresses are refused.',
		displayOptions: { show: { resource: ['webhook'], operation: ['create'] } },
	},
	{
		displayName: 'Webhook ID',
		name: 'webhookId',
		type: 'string',
		default: '',
		required: true,
		displayOptions: { show: { resource: ['webhook'], operation: ['delete', 'test'] } },
	},
];

function assertHash(this: IExecuteFunctions, value: string, itemIndex: number): string {
	const hash = value.trim().toLowerCase();
	if (!SHA256_RE.test(hash)) {
		throw new NodeOperationError(
			this.getNode(),
			'SHA-256 Hash must be 64 hexadecimal characters',
			{ itemIndex },
		);
	}
	return hash;
}

/** n8n's own error classes pass through; anything else is wrapped so the UI shows it properly. */
function asNodeError(this: IExecuteFunctions, error: unknown): Error {
	if (error instanceof NodeApiError || error instanceof NodeOperationError) return error;
	return new NodeApiError(this.getNode(), error as JsonObject);
}

function proofBody(sha256: string, additional: IDataObject, fallbackFilename?: string): IDataObject {
	const body: IDataObject = { sha256 };
	const filename = (additional.filename as string) || fallbackFilename;
	if (filename) body.filename = filename;
	if (additional.externalId) body.external_id = additional.externalId;
	return body;
}

export class ProofLedger implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'ProofLedger',
		name: 'proofLedger',
		icon: { light: 'file:../../icons/proofledger.svg', dark: 'file:../../icons/proofledger.dark.svg' },
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
		description:
			'Anchor a file’s SHA-256 hash on the Polygon blockchain and read proofs back. Only the hash is sent; the file never leaves n8n.',
		defaults: {
			name: 'ProofLedger',
		},
		usableAsTool: true,
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		credentials: [
			{
				name: 'proofLedgerApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Resource',
				name: 'resource',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Account',
						value: 'account',
					},
					{
						name: 'Proof',
						value: 'proof',
					},
					{
						name: 'Webhook',
						value: 'webhook',
					},
				],
				default: 'proof',
			},
			...proofOperations,
			...webhookOperations,
			...accountOperations,
			...proofFields,
			...webhookFields,
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const resource = this.getNodeParameter('resource', 0) as string;
		const operation = this.getNodeParameter('operation', 0) as string;

		if (resource === 'proof' && operation === 'createMany') {
			// One request per 100 items. The API checks every item first and writes them
			// together, so a bad hash in a batch never costs the good ones.
			const entries: Array<{ index: number; body: IDataObject }> = [];
			for (let i = 0; i < items.length; i++) {
				const sha256 = assertHash.call(this, String(this.getNodeParameter('sha256', i)), i);
				const additional = this.getNodeParameter('additionalFields', i, {}) as IDataObject;
				entries.push({ index: i, body: proofBody(sha256, additional) });
			}
			try {
				for (let start = 0; start < entries.length; start += BATCH_SIZE) {
					const chunk = entries.slice(start, start + BATCH_SIZE);
					const response = await proofLedgerApiRequest.call(this, 'POST', '/api/v1/proofs/batch', {
						items: chunk.map((e) => e.body),
					});
					const results = (response.items as IDataObject[]) || [];
					chunk.forEach((entry, position) => {
						const result = results[position] || {};
						returnData.push({
							json: {
								result: result.result ?? null,
								error: result.error ?? null,
								proof: result.proof ?? null,
								batch_id: response.batch_id ?? null,
							},
							pairedItem: { item: entry.index },
						});
					});
				}
			} catch (error) {
				if (this.continueOnFail()) {
					return [items.map((_, i) => ({ json: { error: (error as Error).message }, pairedItem: { item: i } }))];
				}
				throw asNodeError.call(this, error);
			}
			return [returnData];
		}

		for (let i = 0; i < items.length; i++) {
			try {
				let responseData: IDataObject | IDataObject[];

				if (resource === 'proof') {
					if (operation === 'create') {
						const sha256 = assertHash.call(this, String(this.getNodeParameter('sha256', i)), i);
						const additional = this.getNodeParameter('additionalFields', i, {}) as IDataObject;
						responseData = await proofLedgerApiRequest.call(
							this,
							'POST',
							'/api/v1/proof',
							proofBody(sha256, additional),
						);
					} else if (operation === 'createFromFile') {
						const propertyName = this.getNodeParameter('binaryPropertyName', i) as string;
						const binary = this.helpers.assertBinaryData(i, propertyName);
						const buffer = await this.helpers.getBinaryDataBuffer(i, propertyName);
						const sha256 = createHash('sha256').update(buffer).digest('hex');
						const additional = this.getNodeParameter('additionalFields', i, {}) as IDataObject;
						responseData = await proofLedgerApiRequest.call(
							this,
							'POST',
							'/api/v1/proof',
							proofBody(sha256, additional, binary.fileName),
						);
					} else if (operation === 'get') {
						const proofId = encodeURIComponent(String(this.getNodeParameter('proofId', i)).trim());
						responseData = await proofLedgerApiRequest.call(this, 'GET', `/api/v1/proof/${proofId}`);
					} else if (operation === 'getBundle') {
						const proofId = encodeURIComponent(String(this.getNodeParameter('proofId', i)).trim());
						responseData = await proofLedgerApiRequest.call(
							this,
							'GET',
							`/api/v1/proof/${proofId}/bundle`,
						);
					} else if (operation === 'getByExternalId') {
						const externalId = String(this.getNodeParameter('externalId', i));
						const response = await proofLedgerApiRequest.call(this, 'GET', '/api/v1/proofs', undefined, {
							external_id: externalId,
						});
						responseData = (response.proof as IDataObject) ?? response;
					} else if (operation === 'getMany') {
						const returnAll = this.getNodeParameter('returnAll', i) as boolean;
						const filters = this.getNodeParameter('filters', i, {}) as IDataObject;
						const limit = returnAll ? 200 : (this.getNodeParameter('limit', i) as number);
						const proofs: IDataObject[] = [];
						let cursor: number | null | undefined;
						do {
							const qs: IDataObject = { limit: Math.min(limit, 200) };
							if (filters.anchoredSince) qs.anchored_since = filters.anchoredSince;
							if (cursor) qs.cursor = cursor;
							const page = await proofLedgerApiRequest.call(this, 'GET', '/api/v1/proofs', undefined, qs);
							proofs.push(...((page.proofs as IDataObject[]) || []));
							cursor = page.next_cursor as number | null | undefined;
						} while (returnAll && cursor);
						responseData = returnAll ? proofs : proofs.slice(0, limit);
					} else if (operation === 'verify') {
						const sha256 = assertHash.call(this, String(this.getNodeParameter('sha256', i)), i);
						responseData = await proofLedgerApiRequest.call(this, 'GET', '/api/v1/verify', undefined, {
							hash: sha256,
						});
					} else {
						throw new NodeOperationError(this.getNode(), `Unknown operation "${operation}"`, {
							itemIndex: i,
						});
					}
				} else if (resource === 'webhook') {
					if (operation === 'create') {
						const url = String(this.getNodeParameter('url', i)).trim();
						responseData = await proofLedgerApiRequest.call(this, 'POST', '/api/v1/webhooks', {
							url,
							events: ['proof.polygon.anchored'],
						});
					} else if (operation === 'getAll') {
						const response = await proofLedgerApiRequest.call(this, 'GET', '/api/v1/webhooks');
						responseData = (response.endpoints as IDataObject[]) || [];
					} else if (operation === 'delete') {
						const id = encodeURIComponent(String(this.getNodeParameter('webhookId', i)).trim());
						responseData = await proofLedgerApiRequest.call(this, 'DELETE', `/api/v1/webhooks/${id}`);
					} else if (operation === 'test') {
						const id = encodeURIComponent(String(this.getNodeParameter('webhookId', i)).trim());
						responseData = await proofLedgerApiRequest.call(
							this,
							'POST',
							`/api/v1/webhooks/${id}/test`,
						);
					} else {
						throw new NodeOperationError(this.getNode(), `Unknown operation "${operation}"`, {
							itemIndex: i,
						});
					}
				} else if (resource === 'account') {
					responseData = await proofLedgerApiRequest.call(this, 'GET', '/api/v1/branding');
				} else {
					throw new NodeOperationError(this.getNode(), `Unknown resource "${resource}"`, {
						itemIndex: i,
					});
				}

				const executionData = this.helpers.constructExecutionMetaData(
					this.helpers.returnJsonArray(responseData),
					{ itemData: { item: i } },
				);
				returnData.push(...executionData);
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({ json: { error: (error as Error).message }, pairedItem: { item: i } });
					continue;
				}
				throw asNodeError.call(this, error);
			}
		}

		return [returnData];
	}
}
