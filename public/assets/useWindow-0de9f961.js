import{r as u}from"./index-a25acccf.js";function D(e,t){if(e==null)return{};var n={},r=Object.keys(e),o,c;for(c=0;c<r.length;c++)o=r[c],!(t.indexOf(o)>=0)&&(n[o]=e[o]);return n}function M(e){return e&&e.ownerDocument||document}const d=!!(typeof window<"u"&&window.document&&window.document.createElement);var f=!1,a=!1;try{var i={get passive(){return f=!0},get once(){return a=f=!0}};d&&(window.addEventListener("test",i,i),window.removeEventListener("test",i,!0))}catch{}function y(e,t,n,r){if(r&&typeof r!="boolean"&&!a){var o=r.once,c=r.capture,s=n;!a&&o&&(s=n.__once||function m(E){this.removeEventListener(t,m,c),n.call(this,E)},n.__once=s),e.addEventListener(t,s,f?r:c)}e.addEventListener(t,n,r)}function b(e,t,n,r){var o=r&&typeof r!="boolean"?r.capture:r;e.removeEventListener(t,n,o),n.__once&&e.removeEventListener(t,n.__once,o)}function P(e,t,n,r){return y(e,t,n,r),function(){b(e,t,n,r)}}const l=e=>!e||typeof e=="function"?e:t=>{e.current=t};function w(e,t){const n=l(e),r=l(t);return o=>{n&&n(o),r&&r(o)}}function k(e,t){return u.useMemo(()=>w(e,t),[e,t])}function R(e){const t=u.useRef(e);return u.useEffect(()=>{t.current=e},[e]),t}function F(e){const t=R(e);return u.useCallback(function(...n){return t.current&&t.current(...n)},[t])}function O(){return u.useState(null)}function S(){const e=u.useRef(!0),t=u.useRef(()=>e.current);return u.useEffect(()=>(e.current=!0,()=>{e.current=!1}),[]),t.current}function j(e){const t=u.useRef(null);return u.useEffect(()=>{t.current=e}),t.current}const g=typeof global<"u"&&global.navigator&&global.navigator.product==="ReactNative",p=typeof document<"u",q=p||g?u.useLayoutEffect:u.useEffect;var L=Function.prototype.bind.call(Function.prototype.call,[].slice);function A(e,t){return L(e.querySelectorAll(t))}function I(e,t){if(e.contains)return e.contains(t);if(e.compareDocumentPosition)return e===t||!!(e.compareDocumentPosition(t)&16)}const _="data-rr-ui-";function T(e){return`${_}${e}`}const v=u.createContext(d?window:void 0);v.Provider;function x(){return u.useContext(v)}export{D as _,x as a,F as b,d as c,T as d,q as e,S as f,j as g,I as h,O as i,y as j,P as l,M as o,A as q,b as r,k as u};
