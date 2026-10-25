<script setup lang="ts">
import { cn } from '@/lib/utils';
defineProps<{ class?: string; title?: string; description?: string }>();
</script>
<template>
  <div :class="cn('flex flex-col gap-1 p-4 pb-3 sm:p-5 sm:pb-3', $props.class)">
    <h3 v-if="title" class="text-sm font-semibold leading-none">{{ title }}</h3>
    <p v-if="description" class="text-xs leading-relaxed text-muted-foreground">{{ description }}</p>
    <slot />
  </div>
</template>
