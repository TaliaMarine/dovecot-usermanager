<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, ApiError, forceLogin } from '@/api'

defineProps<{ scheme: string }>()

const users = ref<string[]>([])
const loading = ref(true)
const search = ref('')
const snack = ref({ show: false, text: '', color: 'success' })

const filtered = computed(() =>
  users.value.filter((u) => u.includes(search.value.trim().toLowerCase())),
)

function notify(text: string, color = 'success') {
  snack.value = { show: true, text, color }
}

function fail(e: unknown) {
  if (e instanceof ApiError && e.status === 401) {
    forceLogin() // session expired
    return
  }
  notify(e instanceof Error ? e.message : String(e), 'error')
}

async function refresh() {
  loading.value = true
  try {
    users.value = await api.users()
  } catch (e) {
    fail(e)
  } finally {
    loading.value = false
  }
}
onMounted(refresh)

// --- create / set password -------------------------------------------------
const form = ref({
  show: false,
  mode: 'create' as 'create' | 'password',
  name: '',
  password: '',
  generate: true,
  busy: false,
})
const reveal = ref({ show: false, name: '', password: '' })
const nameRule = (v: string) =>
  /^[a-z0-9._+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(v) || 'Lowercase address like name@example.com'
const pwRule = (v: string) => form.value.generate || v.length >= 10 || 'At least 10 characters'

function openCreate() {
  form.value = { show: true, mode: 'create', name: '', password: '', generate: true, busy: false }
}
function openPassword(name: string) {
  form.value = { show: true, mode: 'password', name, password: '', generate: true, busy: false }
}

async function submit() {
  const f = form.value
  if (f.mode === 'create' && nameRule(f.name) !== true) return
  if (pwRule(f.password) !== true) return
  f.busy = true
  try {
    const res =
      f.mode === 'create'
        ? await api.create(f.name, f.password, f.generate)
        : await api.setPassword(f.name, f.password, f.generate)
    f.show = false
    if (res.password) reveal.value = { show: true, name: res.name, password: res.password }
    else notify(f.mode === 'create' ? `Created ${res.name}` : `Password changed for ${res.name}`)
    await refresh()
  } catch (e) {
    fail(e)
  } finally {
    f.busy = false
  }
}

// --- delete ----------------------------------------------------------------
const del = ref({ show: false, name: '', busy: false })
async function confirmDelete() {
  del.value.busy = true
  try {
    await api.remove(del.value.name)
    notify(`Deleted ${del.value.name}`)
    del.value.show = false
    await refresh()
  } catch (e) {
    fail(e)
  } finally {
    del.value.busy = false
  }
}

// --- restart ---------------------------------------------------------------
const restart = ref({ show: false, busy: false })
async function confirmRestart() {
  restart.value.busy = true
  try {
    await api.restart()
    notify('Restart triggered; Dovecot will be back in a moment')
    restart.value.show = false
  } catch (e) {
    fail(e)
  } finally {
    restart.value.busy = false
  }
}

async function copy(text: string) {
  await navigator.clipboard.writeText(text)
  notify('Copied')
}
</script>

<template>
  <v-card>
    <v-card-item>
      <v-card-title>Mailboxes</v-card-title>
      <v-card-subtitle>
        Changes reach Dovecot within about a minute, no restart needed. Hashing: {{ scheme }}.
      </v-card-subtitle>
      <template #append>
        <v-btn class="mr-2" variant="tonal" prepend-icon="mdi-restart" @click="restart.show = true"
          >Restart Dovecot</v-btn
        >
        <v-btn color="primary" variant="flat" prepend-icon="mdi-account-plus" @click="openCreate"
          >Add user</v-btn
        >
      </template>
    </v-card-item>

    <v-card-text class="pb-0">
      <v-text-field
        v-model="search"
        label="Filter"
        prepend-inner-icon="mdi-magnify"
        clearable
        hide-details
        density="compact"
      />
    </v-card-text>

    <v-list lines="one">
      <v-progress-linear v-if="loading" indeterminate />
      <v-list-item v-for="u in filtered" :key="u" :title="u" prepend-icon="mdi-account-outline">
        <template #append>
          <v-btn
            icon="mdi-key-variant"
            variant="text"
            title="Change password"
            @click="openPassword(u)"
          />
          <v-btn
            icon="mdi-delete-outline"
            variant="text"
            color="error"
            title="Delete user"
            @click="del = { show: true, name: u, busy: false }"
          />
        </template>
      </v-list-item>
      <v-list-item v-if="!loading && !filtered.length" class="text-medium-emphasis">
        {{ users.length ? 'No users match the filter.' : 'No users yet.' }}
      </v-list-item>
    </v-list>
  </v-card>

  <v-dialog v-model="form.show" max-width="480" :persistent="form.busy">
    <v-card :title="form.mode === 'create' ? 'Add user' : 'Change password'">
      <v-form @submit.prevent="submit">
        <v-card-text>
          <v-text-field
            v-model="form.name"
            label="Address"
            :readonly="form.mode === 'password'"
            :rules="[nameRule]"
            autofocus
          />
          <v-switch
            v-model="form.generate"
            label="Generate a random password"
            color="primary"
            hide-details
          />
          <v-text-field
            v-if="!form.generate"
            v-model="form.password"
            label="Password"
            type="password"
            autocomplete="new-password"
            :rules="[pwRule]"
            class="mt-2"
          />
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn :disabled="form.busy" @click="form.show = false">Cancel</v-btn>
          <v-btn type="submit" color="primary" variant="flat" :loading="form.busy">Save</v-btn>
        </v-card-actions>
      </v-form>
    </v-card>
  </v-dialog>

  <v-dialog v-model="reveal.show" max-width="480" persistent>
    <v-card title="Generated password">
      <v-card-text>
        <p class="mb-3">
          Password for <strong>{{ reveal.name }}</strong>. It is shown only once.
        </p>
        <v-text-field
          :model-value="reveal.password"
          readonly
          variant="outlined"
          append-inner-icon="mdi-content-copy"
          @click:append-inner="copy(reveal.password)"
        />
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn
          color="primary"
          variant="flat"
          @click="reveal = { show: false, name: '', password: '' }"
          >Done</v-btn
        >
      </v-card-actions>
    </v-card>
  </v-dialog>

  <v-dialog v-model="del.show" max-width="480" :persistent="del.busy">
    <v-card title="Delete user?">
      <v-card-text>
        <strong>{{ del.name }}</strong> can no longer sign in. Their mail on the volume is
        <strong>not</strong> deleted.
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn :disabled="del.busy" @click="del.show = false">Cancel</v-btn>
        <v-btn color="error" variant="flat" :loading="del.busy" @click="confirmDelete"
          >Delete</v-btn
        >
      </v-card-actions>
    </v-card>
  </v-dialog>

  <v-dialog v-model="restart.show" max-width="480" :persistent="restart.busy">
    <v-card title="Restart Dovecot?">
      <v-card-text
        >All open IMAP connections will be dropped while the pod restarts. Only needed for config
        changes; user changes apply on their own.</v-card-text
      >
      <v-card-actions>
        <v-spacer />
        <v-btn :disabled="restart.busy" @click="restart.show = false">Cancel</v-btn>
        <v-btn color="primary" variant="flat" :loading="restart.busy" @click="confirmRestart"
          >Restart</v-btn
        >
      </v-card-actions>
    </v-card>
  </v-dialog>

  <v-snackbar v-model="snack.show" :color="snack.color" timeout="4000">{{ snack.text }}</v-snackbar>
</template>
