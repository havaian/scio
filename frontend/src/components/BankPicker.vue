<script setup lang="ts">
import { computed } from 'vue';
import { Building2, X } from 'lucide-vue-next';
import { setBank, store } from '@/lib/store';
import { ACCESS_LABEL, accessOf } from '@/lib/utils';

// Bank filter shown above every page; the choice applies to all pages until cleared.
const targets = computed(() => store.report?.targets ?? []);
const current = computed(() => targets.value.find((t) => t.id === store.bank));
</script>

<template>
  <div v-if="targets.length" class="mb-4 flex items-center gap-2">
    <label class="relative flex min-w-0 flex-1 items-center sm:flex-none">
      <Building2 class="pointer-events-none absolute left-2.5 size-4 text-muted-foreground" />
      <span class="sr-only">Bank</span>
      <select
        :value="store.bank"
        class="h-10 w-full min-w-0 rounded-md border border-border bg-background pr-8 pl-8 text-sm sm:h-9 sm:w-80"
        :class="store.bank !== 'all' && 'border-foreground/40 font-medium'"
        @change="setBank(($event.target as HTMLSelectElement).value)"
      >
        <option value="all">All banks</option>
        <option v-for="t in targets" :key="t.id" :value="t.id">{{ t.name }}</option>
      </select>
    </label>
    <button v-if="store.bank !== 'all'" type="button" class="inline-flex h-10 shrink-0 items-center gap-1 rounded-md px-2 text-xs text-muted-foreground hover:bg-accent hover:text-foreground sm:h-9" aria-label="Show all banks" @click="setBank('all')">
      <X class="size-4" /><span class="hidden sm:inline">All banks</span>
    </button>
    <span v-if="current" class="hidden truncate text-xs text-muted-foreground md:inline">{{ ACCESS_LABEL[accessOf(current)] }}</span>
  </div>
</template>
