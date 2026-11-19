<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, ApiError, forceLogin, startLogin, type Me } from '@/api'
import UserManager from '@/components/UserManager.vue'

type State = 'loading' | 'ready' | 'error'

const state = ref<State>('loading')
const me = ref<Me | null>(null)
const errorTitle = ref('')
const errorText = ref('')

const authErrors: Record<string, [string, string]> = {
  forbidden: ['Access denied', 'Your account is not a member of the admin group (homelab-admins).'],
  provider_error: ['Sign-in failed', 'The identity provider returned an error.'],
  invalid_state: [
    'Sign-in failed',
    'The login attempt expired or was started in another browser tab. Try again.',
  ],
}

function showError(title: string, text: string) {
  errorTitle.value = title
  errorText.value = text
  state.value = 'error'
}

onMounted(async () => {
  const authError = new URLSearchParams(location.search).get('auth_error')
  if (authError) {
    // Never auto-redirect after a failed login: that would loop.
    history.replaceState(null, '', location.pathname)
    const [title, text] = authErrors[authError] ?? ['Sign-in failed', `Reason: ${authError}`]
    showError(title, text)
    return
  }
  try {
    me.value = await api.me()
    state.value = 'ready'
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      if (!startLogin())
        showError(
          'Sign-in did not stick',
          'Login completed but no session cookie was kept. Check that the site is served over HTTPS and cookies are allowed.',
        )
      return
    }
    showError('Something went wrong', e instanceof Error ? e.message : String(e))
  }
})

async function logout() {
  await api.logout().catch(() => undefined)
  location.reload()
}
</script>

<template>
  <v-app>
    <v-app-bar flat border>
      <v-app-bar-title>
        <v-icon icon="mdi-email-multiple-outline" class="mr-2" />
        Dovecot users
      </v-app-bar-title>
      <template v-if="me" #append>
        <span class="text-medium-emphasis mr-2 d-none d-sm-inline">{{ me.name || me.email }}</span>
        <v-btn icon="mdi-logout" title="Sign out" @click="logout" />
      </template>
    </v-app-bar>

    <v-main>
      <v-container class="py-8" style="max-width: 960px">
        <div v-if="state === 'loading'" class="d-flex justify-center py-16">
          <v-progress-circular indeterminate size="48" />
        </div>

        <v-card v-else-if="state === 'error'" max-width="520" class="mx-auto mt-8">
          <v-card-item prepend-icon="mdi-alert-circle-outline">
            <v-card-title>{{ errorTitle }}</v-card-title>
          </v-card-item>
          <v-card-text>{{ errorText }}</v-card-text>
          <v-card-actions>
            <v-spacer />
            <v-btn color="primary" variant="flat" @click="forceLogin">Try again</v-btn>
          </v-card-actions>
        </v-card>

        <UserManager v-else-if="me" :scheme="me.scheme" />
      </v-container>
    </v-main>
  </v-app>
</template>
