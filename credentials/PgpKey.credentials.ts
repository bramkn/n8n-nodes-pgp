import type { ICredentialType, INodeProperties } from 'n8n-workflow';

// eslint-disable-next-line n8n-nodes-base/cred-class-name-unsuffixed
export class PgpKey implements ICredentialType {
	// eslint-disable-next-line n8n-nodes-base/cred-class-field-name-unsuffixed
	name = 'pgpKey';

	displayName = 'PGP Key';

	properties: INodeProperties[] = [
		{
			displayName: 'Type',
			name: 'type',
			type: 'options',
			options: [
				{
					name: 'Public',
					value: 'public',
				},
				{
					name: 'Private',
					value: 'private',
				},
			],
			default: 'public',
			description:
				'Is this a private key or public key, Public is used to encrypt and Private is used to decrypt',
		},
		{
			displayName: 'Key',
			name: 'key',
			type: 'string',
			typeOptions: {
				password: false,
				rows: 5,
			},
			default: '',
		},
		{
			displayName: 'Passphrase',
			name: 'passphrase',
			type: 'string',
			typeOptions: {
				password: true,
			},
			default: '',
			displayOptions: {
				show: {
					type: ['private'],
				},
			},
		},
	];
}
