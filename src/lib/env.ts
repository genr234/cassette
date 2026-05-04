import z from 'zod';
import * as environment from '$env/dynamic/private';

const schema = z.object({
	AIRTABLE_BASE_ID: z.string().nonempty(),
	AIRTABLE_API_TOKEN: z.string().nonempty(),
	HACKCLUB_CLIENT_ID: z.string().nonempty(),
	HACKCLUB_CLIENT_SECRET: z.string().nonempty(),
	AUTH_DATA_ENCRYPTION_KEY: z.string().min(32).optional()
});

const parsed = schema.safeParse({
	AIRTABLE_BASE_ID: environment.env.AIRTABLE_BASE_ID,
	AIRTABLE_API_TOKEN: environment.env.AIRTABLE_API_TOKEN,
	HACKCLUB_CLIENT_ID: environment.env.HACKCLUB_CLIENT_ID,
	HACKCLUB_CLIENT_SECRET: environment.env.HACKCLUB_CLIENT_SECRET,
	AUTH_DATA_ENCRYPTION_KEY: environment.env.AUTH_DATA_ENCRYPTION_KEY
});

if (!parsed.success) {
	console.error('Failed to validate env: ', parsed.error);
	process.exit(1);
}

export const env = parsed.data;
