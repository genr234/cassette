import { getCallbackResponse } from '$lib/server/auth-routes';
import type { RequestEvent } from '@sveltejs/kit';

export const GET = (event: RequestEvent) => {
	return getCallbackResponse(event);
}