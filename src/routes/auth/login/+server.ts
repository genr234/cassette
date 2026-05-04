import { getLoginResponse } from '$lib/server/auth-routes';
import type { RequestEvent } from '@sveltejs/kit';

export const GET = (event: RequestEvent) => {
	return getLoginResponse(event)
}

export const POST = (event: RequestEvent) => {
	return getLoginResponse(event)
}
