export interface Me {
  name: string
  email: string
  scheme: string
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
  }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: {
      // Required by the backend on every mutating request (CSRF defence).
      'X-Requested-With': 'dovecot-usermanager',
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!res.ok) {
    let msg = res.statusText
    try {
      msg = (await res.json()).error ?? msg
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, msg)
  }
  if (res.status === 204 || res.status === 202) return undefined as T
  return (await res.json()) as T
}

export interface PasswordResult {
  name: string
  password?: string
}

export const api = {
  me: () => call<Me>('GET', '/api/me'),
  users: async () => (await call<{ users: string[] }>('GET', '/api/users')).users,
  create: (name: string, password: string, generate: boolean) =>
    call<PasswordResult>('POST', '/api/users', { name, password, generate }),
  setPassword: (name: string, password: string, generate: boolean) =>
    call<PasswordResult>('PUT', `/api/users/${encodeURIComponent(name)}/password`, {
      password,
      generate,
    }),
  remove: (name: string) => call<void>('DELETE', `/api/users/${encodeURIComponent(name)}`),
  restart: () => call<void>('POST', '/api/restart'),
  logout: () => call<void>('POST', '/api/auth/logout'),
}

const LOGIN_KEY = 'um_last_login_redirect'
const LOOP_WINDOW_MS = 15_000

/**
 * Sends the browser to the OIDC login. Returns false (without navigating)
 * when we already did so moments ago, i.e. the login "succeeded" but the
 * session did not stick; the caller shows an error instead of looping.
 */
export function startLogin(): boolean {
  const last = Number(sessionStorage.getItem(LOGIN_KEY) ?? 0)
  if (Date.now() - last < LOOP_WINDOW_MS) return false
  sessionStorage.setItem(LOGIN_KEY, String(Date.now()))
  const back = location.pathname + location.search
  location.assign('/api/auth/login?return=' + encodeURIComponent(back))
  return true
}

export function forceLogin(): void {
  sessionStorage.removeItem(LOGIN_KEY)
  startLogin()
}
