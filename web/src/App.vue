<script setup lang="ts">
import { onMounted } from 'vue'
import { RouterView } from 'vue-router'

import { session } from './session'

onMounted(() => session.restore())
</script>

<template>
  <div v-if="!session.ready" class="boot-screen">
    <span class="boot-mark" aria-hidden="true"></span>
    <span>正在连接控制器</span>
  </div>
  <RouterView v-else />
</template>
