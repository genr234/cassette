import { env } from '$lib/env';
import { defineAirtableTable } from '$lib/server/airtable';
import z from 'zod';

const prizeSchema = z.object({
	name: z.string(),
	image: z.string(),
	price: z.number()
});

export const Prizes = defineAirtableTable({
	baseId: env.AIRTABLE_BASE_ID,
	tableName: 'Shop',
	schema: prizeSchema
});
