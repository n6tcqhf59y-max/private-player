/**
 * 播放队列：对资料库里的全部条目洗牌后按顺序连播。
 */

function cryptoRandom() {
  const buf = new Uint32Array(1);
  globalThis.crypto.getRandomValues(buf);
  return buf[0] / 0x100000000;
}

export function shuffleCopy(items, randomFn = cryptoRandom) {
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

/**
 * 把资料库里的全部 id 重新洗牌。
 * 多于一条时，尽量不让新队列的第一条跟上一条的结尾相同。
 */
export function nextShuffleQueue(ids, avoidFirst, randomFn) {
  const source = Array.isArray(ids) ? ids.filter((id) => id != null) : [];
  if (!source.length) return createPlayQueue([], { shuffle: true, randomFn });
  let queue = createPlayQueue(source, { shuffle: true, randomFn });
  if (source.length < 2 || avoidFirst == null) return queue;
  let guard = 0;
  while (queue.current === avoidFirst && guard < 8) {
    queue = createPlayQueue(source, { shuffle: true, randomFn });
    guard += 1;
  }
  return queue;
}
