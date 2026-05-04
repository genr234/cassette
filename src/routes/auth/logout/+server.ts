import { getLogoutResponse } from '$lib/server/auth-routes';
import type { RequestEvent } from '@sveltejs/kit';

export const POST = (event: RequestEvent) => {
	return getLogoutResponse(event);
}