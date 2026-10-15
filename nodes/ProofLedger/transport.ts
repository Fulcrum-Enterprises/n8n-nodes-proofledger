import type {
	IDataObject,
	IExecuteFunctions,
	IHookFunctions,
	IHttpRequestMethods,
	IHttpRequestOptions,
	ILoadOptionsFunctions,
	IWebhookFunctions,
} from 'n8n-workflow';

/**
 * One call to the ProofLedger API with the stored credential. The base URL comes
 * from the credential so a self-test against another address needs no code change.
 */
export async function proofLedgerApiRequest(
	this: IExecuteFunctions | IHookFunctions | IWebhookFunctions | ILoadOptionsFunctions,
	method: IHttpRequestMethods,
	endpoint: string,
	body?: IDataObject,
	qs?: IDataObject,
): Promise<IDataObject> {
	const credentials = await this.getCredentials('proofLedgerApi');
	const baseUrl = String(credentials.baseUrl || 'https://proofledger.io').replace(/\/+$/, '');
	const options: IHttpRequestOptions = {
		method,
		url: `${baseUrl}${endpoint}`,
		headers: { Accept: 'application/json' },
		json: true,
	};
	if (body !== undefined) options.body = body;
	if (qs !== undefined && Object.keys(qs).length > 0) options.qs = qs;
	return (await this.helpers.httpRequestWithAuthentication.call(
		this,
		'proofLedgerApi',
		options,
	)) as IDataObject;
}
