<script setup lang="ts">
import { scoreTone } from '@/lib/utils';
defineProps<{ value: number | null | undefined; large?: boolean }>();
</script>
<template>
  <span v-if="value === null || value === undefined" class="text-muted-foreground">-</span>
  <span v-else :class="[scoreTone(value), large ? 'text-3xl font-semibold tabular-nums' : 'font-semibold tabular-nums']">{{ value }}</span>
</template>
