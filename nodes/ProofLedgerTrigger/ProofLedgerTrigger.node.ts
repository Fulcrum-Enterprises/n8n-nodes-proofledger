import { createHmac, timingSafeEqual } from 'crypto';
import type {
	IDataObject,
	IHookFunctions,
	INodeType,
	INodeTypeDescription,
	IWebhookFunctions,
	IWebhookResponseData,
	JsonObject,
} from 'n8n-workflow';
import { NodeApiError, NodeConnectionTypes } from 'n8n-workflow';

import { proofLedgerApiRequest } from '../ProofLedger/transport';

const SIGNATURE_TOLERANCE_SECONDS = 300;

/**
 * ProofLedger signs every delivery: `ProofLedger-Signature: t=<unix seconds>,v1=<hex>`
 * where v1 = HMAC-SHA256(secret, `${t}.${rawBody}`). Same shape as Stripe's.
 */
export function verifySignature(
	secret: string,
	header: string | undefined,
	rawBody: string,
	now: number = Math.floor(Date.now() / 1000),
): boolean {
	if (!header) return false;
	let t: string | undefined;
	let v1: string | undefined;
	for (const part of header.split(',')) {
		const [key, value] = part.trim().split('=', 2);
		if (key === 't') t = value;
		if (key === 'v1') v1 = value;
	}
	if (!t || !v1 || !/^\d+$/.test(t) || !/^[a-f0-9]{64}$/i.test(v1)) return false;
	if (Math.abs(now - Number(t)) > SIGNATURE_TOLERANCE_SECONDS) return false;
	const expected = createHmac('sha256', secret).update(`${t}.${rawBody}`).digest('hex');
	const a = Buffer.from(expected, 'hex');
	const b = Buffer.from(v1, 'hex');
	return a.length === b.length && timingSafeEqual(a, b);
}

function rawBodyOf(req: { rawBody?: unknown; body?: unknown }): string {
	const raw = req.rawBody;
	if (Buffer.isBuffer(raw)) return raw.toString('utf8');
	if (typeof raw === 'string') return raw;
	return JSON.stringify(req.body ?? {});
}

export class ProofLedgerTrigger implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'ProofLedger Trigger',
		name: 'proofLedgerTrigger',
		icon: { light: 'file:../../icons/proofledger.svg', dark: 'file:../../icons/proofledger.dark.svg' },
		group: ['trigger'],
		version: 1,
		subtitle: 'Proof anchored on Polygon',
		description:
			'Starts the workflow when ProofLedger anchors a proof on Polygon. Registers the webhook for you and checks every delivery’s signature.',
		defaults: {
			name: 'ProofLedger Trigger',
		},
		inputs: [],
		outputs: [NodeConnectionTypes.Main],
		credentials: [
			{
				name: 'proofLedgerApi',
				required: true,
			},
		],
		webhooks: [
			{
				name: 'default',
				httpMethod: 'POST',
				responseMode: 'onReceived',
				path: 'webhook',
			},
		],
		properties: [
			{
				displayName:
					'The webhook URL must be reachable from the internet over https. ProofLedger refuses private, loopback and plain http addresses. Each event carries the proof and its verify-proof bundle under data.',
				name: 'notice',
				type: 'notice',
				default: '',
			},
			{
				displayName: 'Include Test Events',
				name: 'includeTestEvents',
				type: 'boolean',
				default: false,
				description:
					'Whether the signed webhook.test event (sent by the webhook test endpoint or the Test button on the ProofLedger account page) also starts the workflow',
			},
		],
	};

	webhookMethods = {
		default: {
			async checkExists(this: IHookFunctions): Promise<boolean> {
				const webhookData = this.getWorkflowStaticData('node');
				if (webhookData.webhookId === undefined) return false;
				const response = await proofLedgerApiRequest.call(this, 'GET', '/api/v1/webhooks');
				const endpoints = (response.endpoints as IDataObject[]) || [];
				const found = endpoints.some(
					(e) => String(e.id) === String(webhookData.webhookId) && e.is_active !== false,
				);
				if (!found) {
					delete webhookData.webhookId;
					delete webhookData.webhookSecret;
				}
				return found;
			},
			async create(this: IHookFunctions): Promise<boolean> {
				const webhookUrl = this.getNodeWebhookUrl('default');
				const response = await proofLedgerApiRequest.call(this, 'POST', '/api/v1/webhooks', {
					url: webhookUrl,
					events: ['proof.polygon.anchored'],
				});
				const endpoint = response.endpoint as IDataObject | undefined;
				if (!endpoint || endpoint.id === undefined || typeof response.secret !== 'string') {
					throw new NodeApiError(this.getNode(), response as JsonObject, {
						message: 'ProofLedger did not return a webhook id and secret.',
					});
				}
				const webhookData = this.getWorkflowStaticData('node');
				webhookData.webhookId = endpoint.id;
				webhookData.webhookSecret = response.secret;
				return true;
			},
			async delete(this: IHookFunctions): Promise<boolean> {
				const webhookData = this.getWorkflowStaticData('node');
				if (webhookData.webhookId !== undefined) {
					try {
						await proofLedgerApiRequest.call(
							this,
							'DELETE',
							`/api/v1/webhooks/${encodeURIComponent(String(webhookData.webhookId))}`,
						);
					} catch (error) {
						this.logger.warn(
							`ProofLedger Trigger: could not delete webhook ${String(webhookData.webhookId)}: ${(error as Error).message}`,
						);
						return false;
					}
					delete webhookData.webhookId;
					delete webhookData.webhookSecret;
				}
				return true;
			},
		},
	};

	async webhook(this: IWebhookFunctions): Promise<IWebhookResponseData> {
		const req = this.getRequestObject();
		const res = this.getResponseObject();
		const webhookData = this.getWorkflowStaticData('node');
		const secret = webhookData.webhookSecret;
		const header = req.header('proofledger-signature');

		if (typeof secret !== 'string' || !verifySignature(secret, header, rawBodyOf(req))) {
			res.status(401).send('Invalid ProofLedger signature').end();
			return { noWebhookResponse: true };
		}

		const body = this.getBodyData();
		const type = body.type as string | undefined;
		const includeTestEvents = this.getNodeParameter('includeTestEvents', false) as boolean;
		if (type === 'webhook.test' && !includeTestEvents) return {};
		if (type !== 'webhook.test' && type !== 'proof.polygon.anchored') return {};

		return {
			workflowData: [this.helpers.returnJsonArray(body)],
		};
	}
}
