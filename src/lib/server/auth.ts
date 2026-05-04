import { env } from '$lib/env';
import { defineAirtableTable } from '$lib/server/airtable';
import { z } from 'zod';
import {
	createCipheriv,
	createDecipheriv,
	createHash,
	randomBytes,
	scryptSync,
	timingSafeEqual
} from 'node:crypto';

const OAUTH_SCOPES = ['openid', 'profile', 'email', 'name', 'slack_id', 'verification_status'];
const HACKCLUB_ISSUER = 'https://auth.hackclub.com';
const AUTH_ENDPOINT = `${HACKCLUB_ISSUER}/oauth/authorize`;
const TOKEN_ENDPOINT = `${HACKCLUB_ISSUER}/oauth/token`;
const ME_ENDPOINT = `${HACKCLUB_ISSUER}/api/v1/me`;

const USER_TABLE = 'Users';
const SESSION_TABLE = 'Sessions';
const ENCRYPTED_VALUE_PREFIX = 'enc:v1:';
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const ENCRYPTION_SALT = 'cassette-auth-token-storage';
const ENCRYPTION_IV_BYTES = 12;
const ENCRYPTION_AUTH_TAG_BYTES = 16;

const cookiesSchema = z.object({
	session: z.string().optional(),
	oauth_state: z.string().optional()
});

const hackClubProfileSchema = z.object({
	sub: z.string(),
	name: z.string().nullable().optional(),
	email: z.email().nullable().optional(),
	picture: z.url().nullable().optional(),
	slack_id: z.string().nullable().optional(),
	verification_status: z.string().nullable().optional(),
	ysws_eligible: z.boolean().nullable().optional()
});

const userSchema = z.object({
	hackclubId: z.string(),
	email: z.email().nullable().optional(),
	name: z.string().nullable().optional(),
	currency: z.number(),
	avatarUrl: z.url().nullable().optional(),
	slackId: z.string().nullable().optional(),
	verificationStatus: z.string().nullable().optional(),
	createdAt: z.string(),
	updatedAt: z.string()
});

const sessionSchema = z.object({
	userId: z.string(),
	tokenHash: z.string(),
	oauthAccessToken: z.string().nullable().optional(),
	oauthRefreshToken: z.string().nullable().optional(),
	oauthScope: z.string().nullable().optional(),
	oauthAccessTokenExpiresAt: z.string().nullable().optional(),
	expiresAt: z.string(),
	createdAt: z.string()
});

const oauthTokenResponseSchema = z.object({
	access_token: z.string().min(1),
	token_type: z.string().min(1),
	expires_in: z.number().int().positive(),
	refresh_token: z.string().min(1),
	scope: z.string().min(1).optional()
});

const usersTable = defineAirtableTable({
	baseId: env.AIRTABLE_BASE_ID,
	tableName: USER_TABLE,
	schema: userSchema
});

const sessionsTable = defineAirtableTable({
	baseId: env.AIRTABLE_BASE_ID,
	tableName: SESSION_TABLE,
	schema: sessionSchema
});

const hashToken = (token: string) => createHash('sha256').update(token).digest('hex');
let encryptionKey: Buffer | null = null;
const getEncryptionKey = () => {
	encryptionKey ??= scryptSync(
		env.AUTH_DATA_ENCRYPTION_KEY ?? env.HACKCLUB_CLIENT_SECRET,
		ENCRYPTION_SALT,
		32
	);
	return encryptionKey;
};

const encryptSecret = (value?: string | null) => {
	if (!value) {
		return value ?? null;
	}

	const iv = randomBytes(12);
	const cipher = createCipheriv(ENCRYPTION_ALGORITHM, getEncryptionKey(), iv);
	const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
	const authTag = cipher.getAuthTag();

	return `${ENCRYPTED_VALUE_PREFIX}${Buffer.concat([iv, authTag, ciphertext]).toString('base64url')}`;
};

const decryptSecret = (value?: string | null) => {
	if (!value) {
		return null;
	}

	if (!value.startsWith(ENCRYPTED_VALUE_PREFIX)) {
		return value;
	}

	try {
		const payload = Buffer.from(value.slice(ENCRYPTED_VALUE_PREFIX.length), 'base64url');
		if (payload.length <= ENCRYPTION_IV_BYTES + ENCRYPTION_AUTH_TAG_BYTES) {
			return null;
		}

		const iv = payload.subarray(0, ENCRYPTION_IV_BYTES);
		const authTag = payload.subarray(
			ENCRYPTION_IV_BYTES,
			ENCRYPTION_IV_BYTES + ENCRYPTION_AUTH_TAG_BYTES
		);
		const ciphertext = payload.subarray(ENCRYPTION_IV_BYTES + ENCRYPTION_AUTH_TAG_BYTES);
		const decipher = createDecipheriv(ENCRYPTION_ALGORITHM, getEncryptionKey(), iv);
		decipher.setAuthTag(authTag);

		return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
	} catch {
		return null;
	}
};

const safeEqual = (left: string, right: string) => {
	const leftBuffer = Buffer.from(left);
	const rightBuffer = Buffer.from(right);
	return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
};

const nowIso = () => new Date().toISOString();

const addDays = (days: number) => {
	const date = new Date();
	date.setDate(date.getDate() + days);
	return date.toISOString();
};

const addSeconds = (seconds: number) => {
	const date = new Date();
	date.setSeconds(date.getSeconds() + seconds);
	return date.toISOString();
};

const normalizeUrl = (url: string) => url.replace(/\/$/, '');

const isExpired = (timestamp?: string | null) => {
	if (!timestamp) {
		return true;
	}

	const parsed = new Date(timestamp);
	if (Number.isNaN(parsed.getTime())) {
		return true;
	}

	return parsed <= new Date();
};

export const buildAuthUrl = (origin: string, state: string) => {
	const params = new URLSearchParams({
		client_id: env.HACKCLUB_CLIENT_ID,
		redirect_uri: `${normalizeUrl(origin)}/auth/callback`,
		response_type: 'code',
		scope: OAUTH_SCOPES.join(' '),
		state
	});

	return `${AUTH_ENDPOINT}?${params.toString()}`;
};

export const generateState = () => randomBytes(16).toString('hex');

const exchangeToken = async (origin: string, code: string) => {
	const params = new URLSearchParams({
		grant_type: 'authorization_code',
		code,
		redirect_uri: `${normalizeUrl(origin)}/auth/callback`,
		client_id: env.HACKCLUB_CLIENT_ID,
		client_secret: env.HACKCLUB_CLIENT_SECRET
	});

	const response = await fetch(TOKEN_ENDPOINT, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded'
		},
		body: params
	});

	if (!response.ok) {
		throw new Error('Failed to exchange OAuth code');
	}

	return oauthTokenResponseSchema.parse(await response.json());
};

const refreshAccessToken = async (refreshToken: string) => {
	const params = new URLSearchParams({
		grant_type: 'refresh_token',
		refresh_token: refreshToken,
		client_id: env.HACKCLUB_CLIENT_ID,
		client_secret: env.HACKCLUB_CLIENT_SECRET
	});

	const response = await fetch(TOKEN_ENDPOINT, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded'
		},
		body: params
	});

	if (!response.ok) {
		throw new Error('Failed to refresh OAuth access token');
	}

	return oauthTokenResponseSchema.parse(await response.json());
};

const fetchProfile = async (accessToken: string) => {
	const response = await fetch(ME_ENDPOINT, {
		headers: {
			Authorization: `Bearer ${accessToken}`
		}
	});

	if (!response.ok) {
		throw new Error('Failed to fetch Hack Club profile');
	}

	const raw = await response.json();
	const identity = typeof raw.identity === 'object' && raw.identity !== null ? raw.identity : raw;

	const userId = identity.sub ?? identity.id ?? identity.user_id ?? identity.uid;
	if (!userId || typeof userId !== 'string') {
		throw new Error('Hack Club profile missing unique ID');
	}

	const normalized: Record<string, unknown> = {
		sub: userId,
		name: identity.first_name ?? null,
		email: identity.primary_email ?? null,
		picture: identity.avatar ?? identity.picture ?? null,
		slack_id: identity.slack_id ?? null,
		verification_status: identity.verification_status ?? null,
		ysws_eligible: identity.ysws_eligible
	};

	return hackClubProfileSchema.parse(normalized);
};

const upsertUser = async (profile: z.infer<typeof hackClubProfileSchema>) => {
	const existing = await usersTable.findOne({ and: [{ field: 'hackclubId', value: profile.sub }] });
	const timestamp = nowIso();

	if (existing) {
		return usersTable.update(existing.id, {
			name: profile.name ?? null,
			email: profile.email ?? null,
			avatarUrl: profile.picture ?? null,
			slackId: profile.slack_id ?? null,
			verificationStatus: profile.verification_status ?? null,
			updatedAt: timestamp
		});
	}

	return usersTable.create({
		hackclubId: profile.sub,
		name: profile.name ?? null,
		currency: 0,
		email: profile.email ?? null,
		avatarUrl: profile.picture ?? null,
		slackId: profile.slack_id ?? null,
		verificationStatus: profile.verification_status ?? null,
		createdAt: timestamp,
		updatedAt: timestamp
	});
};

export const createSession = async (
	userId: string,
	oauth?: z.infer<typeof oauthTokenResponseSchema>
) => {
	const token = randomBytes(32).toString('hex');
	const tokenHash = hashToken(token);
	const session = await sessionsTable.create({
		userId,
		tokenHash,
		oauthAccessToken: encryptSecret(oauth?.access_token),
		oauthRefreshToken: encryptSecret(oauth?.refresh_token),
		oauthScope: oauth?.scope ?? OAUTH_SCOPES.join(' '),
		oauthAccessTokenExpiresAt: oauth ? addSeconds(oauth.expires_in) : null,
		expiresAt: addDays(14),
		createdAt: nowIso()
	});

	return { token, session };
};

export const getSession = async (token: string) => {
	const tokenHash = hashToken(token);
	const record = await sessionsTable.findOne({ and: [{ field: 'tokenHash', value: tokenHash }] });

	if (!record) {
		return null;
	}

	if (isExpired(record.expiresAt)) {
		await sessionsTable.remove(record.id);
		return null;
	}

	return record;
};

export const getAccessTokenForSession = async (token: string) => {
	const session = await getSession(token);
	if (!session) {
		return null;
	}

	if (session.oauthAccessToken && !isExpired(session.oauthAccessTokenExpiresAt)) {
		return decryptSecret(session.oauthAccessToken);
	}

	if (!session.oauthRefreshToken) {
		return null;
	}

	const refreshToken = decryptSecret(session.oauthRefreshToken);
	if (!refreshToken) {
		return null;
	}

	const refreshed = await refreshAccessToken(refreshToken);
	const updated = await sessionsTable.update(session.id, {
		oauthAccessToken: encryptSecret(refreshed.access_token),
		oauthRefreshToken: encryptSecret(refreshed.refresh_token),
		oauthScope: refreshed.scope ?? session.oauthScope ?? OAUTH_SCOPES.join(' '),
		oauthAccessTokenExpiresAt: addSeconds(refreshed.expires_in)
	});

	return decryptSecret(updated.oauthAccessToken);
};

export const deleteSession = async (token: string) => {
	const tokenHash = hashToken(token);
	const record = await sessionsTable.findOne({ and: [{ field: 'tokenHash', value: tokenHash }] });
	if (record) {
		await sessionsTable.remove(record.id);
	}
};

export const clearSessionCookie = (cookies: {
	delete: (name: string, options: { path: string }) => void;
}) => {
	cookies.delete('session', { path: '/' });
};

export const setSessionCookie = (
	cookies: {
		set: (
			name: string,
			value: string,
			options: { path: string; httpOnly: boolean; secure: boolean; sameSite: 'lax'; maxAge: number }
		) => void;
	},
	token: string
) => {
	cookies.set('session', token, {
		path: '/',
		httpOnly: true,
		secure: true,
		sameSite: 'lax',
		maxAge: 60 * 60 * 24 * 14
	});
};

export const getCookies = (cookies: Record<string, string | undefined>) =>
	cookiesSchema.parse(cookies);

export const verifyState = (expectedState: string | undefined, receivedState: string | undefined) =>
	typeof expectedState === 'string' &&
	typeof receivedState === 'string' &&
	expectedState.length > 0 &&
	receivedState.length > 0 &&
	safeEqual(expectedState, receivedState);

export const handleAuthCallback = async (origin: string, code: string) => {
	const tokenResponse = await exchangeToken(origin, code);
	const profile = await fetchProfile(tokenResponse.access_token);
	const user = await upsertUser(profile);
	const session = await createSession(user.id, tokenResponse);
	return { user, sessionToken: session.token };
};

export const getUserById = async (id: string) => usersTable.findById(id);

export type AuthUser = z.infer<typeof userSchema> & { id: string };
