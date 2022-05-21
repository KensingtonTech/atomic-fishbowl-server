export {}

Object.defineProperty(Array.prototype, 'forEachReverse', {
  value: function forEachReverse<T>(callbackfn: (value: T, index: number, array: T[]) => void, thisArg?: any): void {
    const array = this as T[];
    for (let i = array.length - 1; i >= 0; i--) {
      if (thisArg !== undefined) {
        callbackfn.bind(thisArg)(array[i], i, array);
      }
      else {
        callbackfn(array[i], i, array);
      }
    }
  }
});

declare global {
  interface Array<T> {
    forEachReverse(callbackfn: (value: T, index: number, array: T[]) => void, thisArg?: any): void;
  }
}
