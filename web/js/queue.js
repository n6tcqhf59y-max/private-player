/**
 * 播放队列：对库中全部视频洗牌后按顺序连播。
 */

export function shuffleCopy(items, randomFn = Math.random) {
  const list = items.slice();
  for (let i = list.length - 1; i > 0; i--) {
    const j = Math.floor(randomFn() * (i + 1));
    const tmp = list[i];
    list[i] = list[j];
    list[j] = tmp;
  }
  return list;
}

export function createPlayQueue(ids, options = {}) {
  const source = Array.isArray(ids) ? ids.slice() : [];
  const list = options.shuffle ? shuffleCopy(source, options.randomFn) : source;
  let index = Number.isInteger(options.startIndex) ? options.startIndex : 0;
  if (index < 0 || index >= list.length) index = 0;

  return {
    get list() {
      return list.slice();
    },
    get length() {
      return list.length;
    },
    get index() {
      return index;
    },
    get current() {
      return list.length ? list[index] : null;
    },
    hasNext() {
      return index < list.length - 1;
    },
    hasPrev() {
      return index > 0;
    },
    next() {
      if (!this.hasNext()) return null;
      index += 1;
      return list[index];
    },
    prev() {
      if (!this.hasPrev()) return null;
      index -= 1;
      return list[index];
    },
    peekNext() {
      return this.hasNext() ? list[index + 1] : null;
    },
    at(i) {
      if (!Number.isInteger(i) || i < 0 || i >= list.length) return null;
      index = i;
      return list[index];
    },
  };
}
