import{r as o}from"./index-c94b69a8.js";function p(e,t){if(e==null)return{};var n={},r=Object.keys(e),u,c;for(c=0;c<r.length;c++)u=r[c],!(t.indexOf(u)>=0)&&(n[u]=e[u]);return n}function C(e){return e&&e.ownerDocument||document}const d=!!(typeof window<"u"&&window.document&&window.document.createElement);var f=!1,a=!1;try{var i={get passive(){return f=!0},get once(){return a=f=!0}};d&&(window.addEventListener("test",i,i),window.removeEventListener("test",i,!0))}catch{}function w(e,t,n,r){if(r&&typeof r!="boolean"&&!a){var u=r.once,c=r.capture,s=n;!a&&u&&(s=n.__once||function E(l){this.removeEventListener(t,E,c),n.call(this,l)},n.__once=s),e.addEventListener(t,s,f?r:c)}e.addEventListener(t,n,r)}function b(e,t,n,r){var u=r&&typeof r!="boolean"?r.capture:r;e.removeEventListener(t,n,u),n.__once&&e.removeEventListener(t,n.__once,u)}function D(e,t,n,r){return w(e,t,n,r),function(){b(e,t,n,r)}}const v=e=>!e||typeof e=="function"?e:t=>{e.current=t};function g(e,t){const n=v(e),r=v(t);return u=>{n&&n(u),r&&r(u)}}function M(e,t){return o.useMemo(()=>g(e,t),[e,t])}function y(e){const t=o.useRef(e);return o.useEffect(()=>{t.current=e},[e]),t}function k(e){const t=y(e);return o.useCallback(function(...n){return t.current&&t.current(...n)},[t])}function O(){return o.useState(null)}function P(){const e=o.useRef(!0),t=o.useRef(()=>e.current);return o.useEffect(()=>(e.current=!0,()=>{e.current=!1}),[]),t.current}const L=typeof global<"u"&&global.navigator&&global.navigator.product==="ReactNative",R=typeof document<"u",S=R||L?o.useLayoutEffect:o.useEffect;function j(e,t){if(e.contains)return e.contains(t);if(e.compareDocumentPosition)return e===t||!!(e.compareDocumentPosition(t)&16)}const m=o.createContext(d?window:void 0);m.Provider;function x(){return o.useContext(m)}export{p as _,P as a,k as b,d as c,j as d,O as e,M as f,w as g,S as h,D as l,C as o,b as r,x as u};
