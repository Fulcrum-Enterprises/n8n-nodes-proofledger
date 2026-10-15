import type {
	IAuthenticateGeneric,
	Icon,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class ProofLedgerApi implements ICredentialType {
	name = 'proofLedgerApi';

	displayName = 'ProofLedger API';

	icon: Icon = { light: 'file:../icons/proofledger.svg', dark: 'file:../icons/proofledger.dark.svg' };

	documentationUrl = 'https://proofledger.io/api.html';

	properties: INodeProperties[] = [
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			required: true,
			description:
				'Issued from Account > API Keys on any ProofLedger plan, including Free. Starts with sk_ and is shown once.',
		},
		{
			displayName: 'Base URL',
			name: 'baseUrl',
			type: 'string',
			default: 'https://proofledger.io',
			description: 'Leave as is unless ProofLedger gives you another address',
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				Authorization: '=Bearer {{$credentials.apiKey}}',
			},
		},
	};

	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.baseUrl}}',
			url: '/api/v1/branding',
			method: 'GET',
		},
	};
}
