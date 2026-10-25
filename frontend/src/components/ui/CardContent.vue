<script setup lang="ts">
import { cn } from '@/lib/utils';
defineProps<{ class?: string }>();
</script>
<template>
  <div :class="cn('p-4 pt-0 sm:p-5 sm:pt-0', $props.class)"><slot /></div>
</template>
