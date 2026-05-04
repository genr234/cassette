import Airtable from 'airtable';
import type { FieldSet, Record as AirtableRecordType } from 'airtable';
import { env } from '$lib/env';
import { z } from 'zod';

const baseIdSchema = z.string().min(3, 'Airtable base id is required');
const tableIdSchema = z.string().min(1, 'Airtable table name is required');

const airtablePat = z.string().min(1);

const envSchema = z.object({
	AIRTABLE_API_TOKEN: airtablePat
});

let airtableApi: Airtable | null = null;

const init = () => {
	if (airtableApi) {
		return;
	}

	const parsedEnv = envSchema.safeParse({
		AIRTABLE_API_TOKEN: env.AIRTABLE_API_TOKEN
	});

	if (!parsedEnv.success) {
		throw new Error('Missing Airtable env vars: AIRTABLE_API_TOKEN');
	}

	const { AIRTABLE_API_TOKEN } = parsedEnv.data;

	airtableApi = new Airtable({
		apiKey: AIRTABLE_API_TOKEN
	});
};

const sanitizeFilterValue = (value: string) => value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');

const escapeFieldName = (field: string) => field.replace(/}/g, '}}');

const buildEqualityFormula = (field: string, value: string | number | boolean) => {
	const safeField = `{${escapeFieldName(field)}}`;

	if (typeof value === 'string') {
		return `IF(${safeField}="${sanitizeFilterValue(value)}", TRUE(), FALSE())`;
	}

	return `IF(${safeField}=${String(value)}, TRUE(), FALSE())`;
};

const isSingleRecord = <T>(records: T[]): records is [T] => records.length === 1;

export type AirtableRecord<T> = T & { id: string };

export type AirtableTableConfig<TSchema extends z.ZodObject<z.ZodRawShape>> = {
	baseId: string;
	tableName: string;
	schema: TSchema;
};

export type AirtableSortDirection = 'asc' | 'desc';

export type AirtableSort = {
	field: string;
	direction?: AirtableSortDirection;
};

export type AirtableQueryOptions = {
	maxRecords?: number;
	sort?: AirtableSort[];
	filterByFormula?: string;
	cacheTtl?: number;
};

export type AirtableCacheOptions = {
	cacheTtl?: number;
};

export type AirtableEqualityFilter = {
	field: string;
	value: string | number | boolean;
};

export type AirtableFilterOptions = {
	and?: AirtableEqualityFilter[];
	or?: AirtableEqualityFilter[];
};

const normalizeEqualityFilters = (filters?: AirtableFilterOptions) => {
	const andFilters = filters?.and ?? [];
	const orFilters = filters?.or ?? [];

	if (andFilters.length === 0 && orFilters.length === 0) {
		return undefined;
	}

	const clauses = [
		...andFilters.map((filter) => buildEqualityFormula(filter.field, filter.value)),
		...orFilters.map((filter) => buildEqualityFormula(filter.field, filter.value))
	];

	if (andFilters.length > 0 && orFilters.length > 0) {
		return `AND(${clauses.join(',')})`;
	}

	if (andFilters.length > 0) {
		return andFilters.length === 1 ? clauses[0] : `AND(${clauses.join(',')})`;
	}

	return orFilters.length === 1 ? clauses[0] : `OR(${clauses.join(',')})`;
};

const toRecord = <TSchema extends z.ZodTypeAny>(
	record: AirtableRecordType<FieldSet>,
	schema: TSchema
): AirtableRecord<z.output<TSchema>> => {
	const parsed = schema.safeParse(record.fields);
	if (!parsed.success) {
		throw new Error(`Invalid Airtable record for ${record.id}`);
	}
	return {
		id: record.id,
		...(parsed.data as Record<string, unknown>)
	} as AirtableRecord<z.output<TSchema>>;
};

const toRecords = <TSchema extends z.ZodTypeAny>(
	records: readonly AirtableRecordType<FieldSet>[],
	schema: TSchema
) => records.map((record) => toRecord(record, schema));

const ensureApi = () => {
	init();

	if (!airtableApi) {
		throw new Error('Airtable client not initialized');
	}

	return airtableApi;
};

export const defineAirtableTable = <TSchema extends z.ZodObject<z.ZodRawShape>>(
	config: AirtableTableConfig<TSchema>
) => {
	const { baseId, tableName, schema } = config;
	const baseIdParsed = baseIdSchema.parse(baseId);
	const tableNameParsed = tableIdSchema.parse(tableName);

	const getTable = () => ensureApi().base(baseIdParsed)(tableNameParsed);
	const applyDefaults = (options: AirtableQueryOptions = {}) => {
		const { filterByFormula, cacheTtl, ...rest } = options;
		return rest;
	};

	const cache = new Map<string, { data: any; expiresAt: number }>();

	const withCache = async <T>(
		key: string,
		ttl: number | undefined,
		fetcher: () => Promise<T>
	): Promise<T> => {
		if (ttl === undefined) {
			return fetcher();
		}

		const cached = cache.get(key);
		if (cached && cached.expiresAt > Date.now()) {
			return cached.data;
		}

		const data = await fetcher();
		cache.set(key, { data, expiresAt: Date.now() + ttl });
		return data;
	};

	return {
		schema,
		async findMany(
			options: AirtableQueryOptions = {},
			filters?: AirtableFilterOptions
		): Promise<AirtableRecord<z.output<TSchema>>[]> {
			const filterByFormula = options.filterByFormula ?? normalizeEqualityFilters(filters);
			const cacheKey = `findMany:${JSON.stringify({ options, filters, filterByFormula })}`;

			return withCache(cacheKey, options.cacheTtl, async () => {
				const table = getTable();
				const selectOptions: AirtableQueryOptions = { ...applyDefaults(options) };
				if (filterByFormula !== undefined) {
					selectOptions.filterByFormula = filterByFormula;
				}

				const records = await table.select(selectOptions).all();
				return toRecords(records, schema);
			});
		},
		async findOne(
			filters: AirtableFilterOptions,
			options: AirtableCacheOptions = {}
		): Promise<AirtableRecord<z.output<TSchema>> | null> {
			const filterByFormula = normalizeEqualityFilters(filters);
			const cacheKey = `findOne:${JSON.stringify({ filters, filterByFormula })}`;

			if (!filterByFormula) {
				throw new Error('findOne requires at least one filter');
			}

			return withCache(cacheKey, options.cacheTtl, async () => {
				const table = getTable();
				const records = await table
					.select({
						...applyDefaults({ maxRecords: 2 }),
						filterByFormula
					})
					.all();

				const parsed = toRecords(records, schema);

				if (parsed.length === 0) {
					return null;
				}

				if (!isSingleRecord(parsed)) {
					throw new Error('findOne matched multiple records');
				}

				return parsed[0];
			});
		},
		async findById(
			id: string,
			options: AirtableCacheOptions = {}
		): Promise<AirtableRecord<z.output<TSchema>> | null> {
			const cacheKey = `findById:${id}`;

			return withCache(cacheKey, options.cacheTtl, async () => {
				const table = getTable();
				try {
					const record = await table.find(id);
					return toRecord(record as AirtableRecordType<FieldSet>, schema);
				} catch {
					return null;
				}
			});
		},
		async create(input: z.input<TSchema>): Promise<AirtableRecord<z.output<TSchema>>> {
			const table = getTable();
			const parsed = schema.parse(input) as FieldSet;
			const record = await table.create(parsed, { typecast: true });
			return toRecord(record as AirtableRecordType<FieldSet>, schema);
		},
		async update(
			id: string,
			input: Partial<z.input<TSchema>>
		): Promise<AirtableRecord<z.output<TSchema>>> {
			const table = getTable();
			const parsed = schema.partial().parse(input) as Partial<FieldSet>;
			const record = await table.update(id, parsed, { typecast: true });
			return toRecord(record as AirtableRecordType<FieldSet>, schema);
		},
		async remove(id: string): Promise<{ id: string }> {
			const table = getTable();
			const record = await table.destroy(id);
			return { id: record.id };
		}
	};
};
