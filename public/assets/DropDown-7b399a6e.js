import{r as d,j as k,n as lr,R as _,u as te,c as re,b as fr}from"./index-95294c57.js";import{_ as pr,b as q,f as dr,h as at,o as vr,l as De,i as mr,d as Ct,a as gr,g as hr,q as it,j as wr,u as Dt,e as yr}from"./useWindow-d182fb8b.js";import{u as br,a as xr,B as $r}from"./Button-1fdb23ab.js";function Le(){return Le=Object.assign?Object.assign.bind():function(e){for(var t=1;t<arguments.length;t++){var r=arguments[t];for(var n in r)Object.prototype.hasOwnProperty.call(r,n)&&(e[n]=r[n])}return e},Le.apply(this,arguments)}function st(e){return"default"+e.charAt(0).toUpperCase()+e.substr(1)}function Or(e){var t=Cr(e,"string");return typeof t=="symbol"?t:String(t)}function Cr(e,t){if(typeof e!="object"||e===null)return e;var r=e[Symbol.toPrimitive];if(r!==void 0){var n=r.call(e,t||"default");if(typeof n!="object")return n;throw new TypeError("@@toPrimitive must return a primitive value.")}return(t==="string"?String:Number)(e)}function Dr(e,t,r){var n=d.useRef(e!==void 0),o=d.useState(t),a=o[0],u=o[1],c=e!==void 0,i=n.current;return n.current=c,!c&&i&&a!==t&&u(t),[c?e:a,d.useCallback(function(l){for(var s=arguments.length,f=new Array(s>1?s-1:0),m=1;m<s;m++)f[m-1]=arguments[m];r&&r.apply(void 0,[l].concat(f)),u(l)},[r])]}function jr(e,t){return Object.keys(t).reduce(function(r,n){var o,a=r,u=a[st(n)],c=a[n],i=pr(a,[st(n),n].map(Or)),l=t[n],s=Dr(c,u,e[l]),f=s[0],m=s[1];return Le({},i,(o={},o[n]=f,o[l]=m,o))},e)}function Pr(e,t,r,n=!1){const o=q(r);d.useEffect(()=>{const a=typeof e=="function"?e():e;return a.addEventListener(t,o,n),()=>a.removeEventListener(t,o,n)},[e])}const Sr=["onKeyDown"];function Ar(e,t){if(e==null)return{};var r={},n=Object.keys(e),o,a;for(a=0;a<n.length;a++)o=n[a],!(t.indexOf(o)>=0)&&(r[o]=e[o]);return r}function Er(e){return!e||e.trim()==="#"}const jt=d.forwardRef((e,t)=>{let{onKeyDown:r}=e,n=Ar(e,Sr);const[o]=br(Object.assign({tagName:"a"},n)),a=q(u=>{o.onKeyDown(u),r==null||r(u)});return Er(n.href)||n.role==="button"?k.jsx("a",Object.assign({ref:t},n,o,{onKeyDown:a})):k.jsx("a",Object.assign({ref:t},n,{onKeyDown:r}))});jt.displayName="Anchor";const kr=jt;function Mr(e,t,r){const n=d.useRef(e!==void 0),[o,a]=d.useState(t),u=e!==void 0,c=n.current;return n.current=u,!u&&c&&o!==t&&a(t),[u?e:o,d.useCallback((...i)=>{const[l,...s]=i;let f=r==null?void 0:r(l,...s);return a(l),f},[r])]}function Rr(){const[,e]=d.useReducer(t=>!t,!1);return e}const Tr=d.createContext(null),ke=Tr;var ct=Object.prototype.hasOwnProperty;function ut(e,t,r){for(r of e.keys())if(ve(r,t))return r}function ve(e,t){var r,n,o;if(e===t)return!0;if(e&&t&&(r=e.constructor)===t.constructor){if(r===Date)return e.getTime()===t.getTime();if(r===RegExp)return e.toString()===t.toString();if(r===Array){if((n=e.length)===t.length)for(;n--&&ve(e[n],t[n]););return n===-1}if(r===Set){if(e.size!==t.size)return!1;for(n of e)if(o=n,o&&typeof o=="object"&&(o=ut(t,o),!o)||!t.has(o))return!1;return!0}if(r===Map){if(e.size!==t.size)return!1;for(n of e)if(o=n[0],o&&typeof o=="object"&&(o=ut(t,o),!o)||!ve(n[1],t.get(o)))return!1;return!0}if(r===ArrayBuffer)e=new Uint8Array(e),t=new Uint8Array(t);else if(r===DataView){if((n=e.byteLength)===t.byteLength)for(;n--&&e.getInt8(n)===t.getInt8(n););return n===-1}if(ArrayBuffer.isView(e)){if((n=e.byteLength)===t.byteLength)for(;n--&&e[n]===t[n];);return n===-1}if(!r||typeof e=="object"){n=0;for(r in e)if(ct.call(e,r)&&++n&&!ct.call(t,r)||!(r in t)||!ve(e[r],t[r]))return!1;return Object.keys(t).length===n}}return e!==e&&t!==t}function Nr(e){const t=dr();return[e[0],d.useCallback(r=>{if(t())return e[1](r)},[t,e[1]])]}var B="top",H="bottom",F="right",I="left",Ke="auto",ye=[B,H,F,I],ae="start",he="end",Br="clippingParents",Pt="viewport",pe="popper",Ir="reference",lt=ye.reduce(function(e,t){return e.concat([t+"-"+ae,t+"-"+he])},[]),St=[].concat(ye,[Ke]).reduce(function(e,t){return e.concat([t,t+"-"+ae,t+"-"+he])},[]),Lr="beforeRead",Wr="read",Hr="afterRead",Fr="beforeMain",Kr="main",Vr="afterMain",Ur="beforeWrite",qr="write",zr="afterWrite",Xr=[Lr,Wr,Hr,Fr,Kr,Vr,Ur,qr,zr];function V(e){return e.split("-")[0]}function W(e){if(e==null)return window;if(e.toString()!=="[object Window]"){var t=e.ownerDocument;return t&&t.defaultView||window}return e}function ee(e){var t=W(e).Element;return e instanceof t||e instanceof Element}function U(e){var t=W(e).HTMLElement;return e instanceof t||e instanceof HTMLElement}function Ve(e){if(typeof ShadowRoot>"u")return!1;var t=W(e).ShadowRoot;return e instanceof t||e instanceof ShadowRoot}var Z=Math.max,Ae=Math.min,ie=Math.round;function We(){var e=navigator.userAgentData;return e!=null&&e.brands&&Array.isArray(e.brands)?e.brands.map(function(t){return t.brand+"/"+t.version}).join(" "):navigator.userAgent}function At(){return!/^((?!chrome|android).)*safari/i.test(We())}function se(e,t,r){t===void 0&&(t=!1),r===void 0&&(r=!1);var n=e.getBoundingClientRect(),o=1,a=1;t&&U(e)&&(o=e.offsetWidth>0&&ie(n.width)/e.offsetWidth||1,a=e.offsetHeight>0&&ie(n.height)/e.offsetHeight||1);var u=ee(e)?W(e):window,c=u.visualViewport,i=!At()&&r,l=(n.left+(i&&c?c.offsetLeft:0))/o,s=(n.top+(i&&c?c.offsetTop:0))/a,f=n.width/o,m=n.height/a;return{width:f,height:m,top:s,right:l+f,bottom:s+m,left:l,x:l,y:s}}function Ue(e){var t=se(e),r=e.offsetWidth,n=e.offsetHeight;return Math.abs(t.width-r)<=1&&(r=t.width),Math.abs(t.height-n)<=1&&(n=t.height),{x:e.offsetLeft,y:e.offsetTop,width:r,height:n}}function Et(e,t){var r=t.getRootNode&&t.getRootNode();if(e.contains(t))return!0;if(r&&Ve(r)){var n=t;do{if(n&&e.isSameNode(n))return!0;n=n.parentNode||n.host}while(n)}return!1}function Y(e){return e?(e.nodeName||"").toLowerCase():null}function z(e){return W(e).getComputedStyle(e)}function Yr(e){return["table","td","th"].indexOf(Y(e))>=0}function G(e){return((ee(e)?e.ownerDocument:e.document)||window.document).documentElement}function Me(e){return Y(e)==="html"?e:e.assignedSlot||e.parentNode||(Ve(e)?e.host:null)||G(e)}function ft(e){return!U(e)||z(e).position==="fixed"?null:e.offsetParent}function Gr(e){var t=/firefox/i.test(We()),r=/Trident/i.test(We());if(r&&U(e)){var n=z(e);if(n.position==="fixed")return null}var o=Me(e);for(Ve(o)&&(o=o.host);U(o)&&["html","body"].indexOf(Y(o))<0;){var a=z(o);if(a.transform!=="none"||a.perspective!=="none"||a.contain==="paint"||["transform","perspective"].indexOf(a.willChange)!==-1||t&&a.willChange==="filter"||t&&a.filter&&a.filter!=="none")return o;o=o.parentNode}return null}function be(e){for(var t=W(e),r=ft(e);r&&Yr(r)&&z(r).position==="static";)r=ft(r);return r&&(Y(r)==="html"||Y(r)==="body"&&z(r).position==="static")?t:r||Gr(e)||t}function qe(e){return["top","bottom"].indexOf(e)>=0?"x":"y"}function me(e,t,r){return Z(e,Ae(t,r))}function Jr(e,t,r){var n=me(e,t,r);return n>r?r:n}function kt(){return{top:0,right:0,bottom:0,left:0}}function Mt(e){return Object.assign({},kt(),e)}function Rt(e,t){return t.reduce(function(r,n){return r[n]=e,r},{})}var Qr=function(t,r){return t=typeof t=="function"?t(Object.assign({},r.rects,{placement:r.placement})):t,Mt(typeof t!="number"?t:Rt(t,ye))};function Zr(e){var t,r=e.state,n=e.name,o=e.options,a=r.elements.arrow,u=r.modifiersData.popperOffsets,c=V(r.placement),i=qe(c),l=[I,F].indexOf(c)>=0,s=l?"height":"width";if(!(!a||!u)){var f=Qr(o.padding,r),m=Ue(a),p=i==="y"?B:I,g=i==="y"?H:F,h=r.rects.reference[s]+r.rects.reference[i]-u[i]-r.rects.popper[s],v=u[i]-r.rects.reference[i],$=be(a),b=$?i==="y"?$.clientHeight||0:$.clientWidth||0:0,x=h/2-v/2,w=f[p],y=b-m[s]-f[g],C=b/2-m[s]/2+x,D=me(w,C,y),P=i;r.modifiersData[n]=(t={},t[P]=D,t.centerOffset=D-C,t)}}function _r(e){var t=e.state,r=e.options,n=r.element,o=n===void 0?"[data-popper-arrow]":n;o!=null&&(typeof o=="string"&&(o=t.elements.popper.querySelector(o),!o)||Et(t.elements.popper,o)&&(t.elements.arrow=o))}const en={name:"arrow",enabled:!0,phase:"main",fn:Zr,effect:_r,requires:["popperOffsets"],requiresIfExists:["preventOverflow"]};function ce(e){return e.split("-")[1]}var tn={top:"auto",right:"auto",bottom:"auto",left:"auto"};function rn(e,t){var r=e.x,n=e.y,o=t.devicePixelRatio||1;return{x:ie(r*o)/o||0,y:ie(n*o)/o||0}}function pt(e){var t,r=e.popper,n=e.popperRect,o=e.placement,a=e.variation,u=e.offsets,c=e.position,i=e.gpuAcceleration,l=e.adaptive,s=e.roundOffsets,f=e.isFixed,m=u.x,p=m===void 0?0:m,g=u.y,h=g===void 0?0:g,v=typeof s=="function"?s({x:p,y:h}):{x:p,y:h};p=v.x,h=v.y;var $=u.hasOwnProperty("x"),b=u.hasOwnProperty("y"),x=I,w=B,y=window;if(l){var C=be(r),D="clientHeight",P="clientWidth";if(C===W(r)&&(C=G(r),z(C).position!=="static"&&c==="absolute"&&(D="scrollHeight",P="scrollWidth")),C=C,o===B||(o===I||o===F)&&a===he){w=H;var E=f&&C===y&&y.visualViewport?y.visualViewport.height:C[D];h-=E-n.height,h*=i?1:-1}if(o===I||(o===B||o===H)&&a===he){x=F;var A=f&&C===y&&y.visualViewport?y.visualViewport.width:C[P];p-=A-n.width,p*=i?1:-1}}var O=Object.assign({position:c},l&&tn),j=s===!0?rn({x:p,y:h},W(r)):{x:p,y:h};if(p=j.x,h=j.y,i){var S;return Object.assign({},O,(S={},S[w]=b?"0":"",S[x]=$?"0":"",S.transform=(y.devicePixelRatio||1)<=1?"translate("+p+"px, "+h+"px)":"translate3d("+p+"px, "+h+"px, 0)",S))}return Object.assign({},O,(t={},t[w]=b?h+"px":"",t[x]=$?p+"px":"",t.transform="",t))}function nn(e){var t=e.state,r=e.options,n=r.gpuAcceleration,o=n===void 0?!0:n,a=r.adaptive,u=a===void 0?!0:a,c=r.roundOffsets,i=c===void 0?!0:c,l={placement:V(t.placement),variation:ce(t.placement),popper:t.elements.popper,popperRect:t.rects.popper,gpuAcceleration:o,isFixed:t.options.strategy==="fixed"};t.modifiersData.popperOffsets!=null&&(t.styles.popper=Object.assign({},t.styles.popper,pt(Object.assign({},l,{offsets:t.modifiersData.popperOffsets,position:t.options.strategy,adaptive:u,roundOffsets:i})))),t.modifiersData.arrow!=null&&(t.styles.arrow=Object.assign({},t.styles.arrow,pt(Object.assign({},l,{offsets:t.modifiersData.arrow,position:"absolute",adaptive:!1,roundOffsets:i})))),t.attributes.popper=Object.assign({},t.attributes.popper,{"data-popper-placement":t.placement})}const on={name:"computeStyles",enabled:!0,phase:"beforeWrite",fn:nn,data:{}};var je={passive:!0};function an(e){var t=e.state,r=e.instance,n=e.options,o=n.scroll,a=o===void 0?!0:o,u=n.resize,c=u===void 0?!0:u,i=W(t.elements.popper),l=[].concat(t.scrollParents.reference,t.scrollParents.popper);return a&&l.forEach(function(s){s.addEventListener("scroll",r.update,je)}),c&&i.addEventListener("resize",r.update,je),function(){a&&l.forEach(function(s){s.removeEventListener("scroll",r.update,je)}),c&&i.removeEventListener("resize",r.update,je)}}const sn={name:"eventListeners",enabled:!0,phase:"write",fn:function(){},effect:an,data:{}};var cn={left:"right",right:"left",bottom:"top",top:"bottom"};function Se(e){return e.replace(/left|right|bottom|top/g,function(t){return cn[t]})}var un={start:"end",end:"start"};function dt(e){return e.replace(/start|end/g,function(t){return un[t]})}function ze(e){var t=W(e),r=t.pageXOffset,n=t.pageYOffset;return{scrollLeft:r,scrollTop:n}}function Xe(e){return se(G(e)).left+ze(e).scrollLeft}function ln(e,t){var r=W(e),n=G(e),o=r.visualViewport,a=n.clientWidth,u=n.clientHeight,c=0,i=0;if(o){a=o.width,u=o.height;var l=At();(l||!l&&t==="fixed")&&(c=o.offsetLeft,i=o.offsetTop)}return{width:a,height:u,x:c+Xe(e),y:i}}function fn(e){var t,r=G(e),n=ze(e),o=(t=e.ownerDocument)==null?void 0:t.body,a=Z(r.scrollWidth,r.clientWidth,o?o.scrollWidth:0,o?o.clientWidth:0),u=Z(r.scrollHeight,r.clientHeight,o?o.scrollHeight:0,o?o.clientHeight:0),c=-n.scrollLeft+Xe(e),i=-n.scrollTop;return z(o||r).direction==="rtl"&&(c+=Z(r.clientWidth,o?o.clientWidth:0)-a),{width:a,height:u,x:c,y:i}}function Ye(e){var t=z(e),r=t.overflow,n=t.overflowX,o=t.overflowY;return/auto|scroll|overlay|hidden/.test(r+o+n)}function Tt(e){return["html","body","#document"].indexOf(Y(e))>=0?e.ownerDocument.body:U(e)&&Ye(e)?e:Tt(Me(e))}function ge(e,t){var r;t===void 0&&(t=[]);var n=Tt(e),o=n===((r=e.ownerDocument)==null?void 0:r.body),a=W(n),u=o?[a].concat(a.visualViewport||[],Ye(n)?n:[]):n,c=t.concat(u);return o?c:c.concat(ge(Me(u)))}function He(e){return Object.assign({},e,{left:e.x,top:e.y,right:e.x+e.width,bottom:e.y+e.height})}function pn(e,t){var r=se(e,!1,t==="fixed");return r.top=r.top+e.clientTop,r.left=r.left+e.clientLeft,r.bottom=r.top+e.clientHeight,r.right=r.left+e.clientWidth,r.width=e.clientWidth,r.height=e.clientHeight,r.x=r.left,r.y=r.top,r}function vt(e,t,r){return t===Pt?He(ln(e,r)):ee(t)?pn(t,r):He(fn(G(e)))}function dn(e){var t=ge(Me(e)),r=["absolute","fixed"].indexOf(z(e).position)>=0,n=r&&U(e)?be(e):e;return ee(n)?t.filter(function(o){return ee(o)&&Et(o,n)&&Y(o)!=="body"}):[]}function vn(e,t,r,n){var o=t==="clippingParents"?dn(e):[].concat(t),a=[].concat(o,[r]),u=a[0],c=a.reduce(function(i,l){var s=vt(e,l,n);return i.top=Z(s.top,i.top),i.right=Ae(s.right,i.right),i.bottom=Ae(s.bottom,i.bottom),i.left=Z(s.left,i.left),i},vt(e,u,n));return c.width=c.right-c.left,c.height=c.bottom-c.top,c.x=c.left,c.y=c.top,c}function Nt(e){var t=e.reference,r=e.element,n=e.placement,o=n?V(n):null,a=n?ce(n):null,u=t.x+t.width/2-r.width/2,c=t.y+t.height/2-r.height/2,i;switch(o){case B:i={x:u,y:t.y-r.height};break;case H:i={x:u,y:t.y+t.height};break;case F:i={x:t.x+t.width,y:c};break;case I:i={x:t.x-r.width,y:c};break;default:i={x:t.x,y:t.y}}var l=o?qe(o):null;if(l!=null){var s=l==="y"?"height":"width";switch(a){case ae:i[l]=i[l]-(t[s]/2-r[s]/2);break;case he:i[l]=i[l]+(t[s]/2-r[s]/2);break}}return i}function we(e,t){t===void 0&&(t={});var r=t,n=r.placement,o=n===void 0?e.placement:n,a=r.strategy,u=a===void 0?e.strategy:a,c=r.boundary,i=c===void 0?Br:c,l=r.rootBoundary,s=l===void 0?Pt:l,f=r.elementContext,m=f===void 0?pe:f,p=r.altBoundary,g=p===void 0?!1:p,h=r.padding,v=h===void 0?0:h,$=Mt(typeof v!="number"?v:Rt(v,ye)),b=m===pe?Ir:pe,x=e.rects.popper,w=e.elements[g?b:m],y=vn(ee(w)?w:w.contextElement||G(e.elements.popper),i,s,u),C=se(e.elements.reference),D=Nt({reference:C,element:x,strategy:"absolute",placement:o}),P=He(Object.assign({},x,D)),E=m===pe?P:C,A={top:y.top-E.top+$.top,bottom:E.bottom-y.bottom+$.bottom,left:y.left-E.left+$.left,right:E.right-y.right+$.right},O=e.modifiersData.offset;if(m===pe&&O){var j=O[o];Object.keys(A).forEach(function(S){var M=[F,H].indexOf(S)>=0?1:-1,N=[B,H].indexOf(S)>=0?"y":"x";A[S]+=j[N]*M})}return A}function mn(e,t){t===void 0&&(t={});var r=t,n=r.placement,o=r.boundary,a=r.rootBoundary,u=r.padding,c=r.flipVariations,i=r.allowedAutoPlacements,l=i===void 0?St:i,s=ce(n),f=s?c?lt:lt.filter(function(g){return ce(g)===s}):ye,m=f.filter(function(g){return l.indexOf(g)>=0});m.length===0&&(m=f);var p=m.reduce(function(g,h){return g[h]=we(e,{placement:h,boundary:o,rootBoundary:a,padding:u})[V(h)],g},{});return Object.keys(p).sort(function(g,h){return p[g]-p[h]})}function gn(e){if(V(e)===Ke)return[];var t=Se(e);return[dt(e),t,dt(t)]}function hn(e){var t=e.state,r=e.options,n=e.name;if(!t.modifiersData[n]._skip){for(var o=r.mainAxis,a=o===void 0?!0:o,u=r.altAxis,c=u===void 0?!0:u,i=r.fallbackPlacements,l=r.padding,s=r.boundary,f=r.rootBoundary,m=r.altBoundary,p=r.flipVariations,g=p===void 0?!0:p,h=r.allowedAutoPlacements,v=t.options.placement,$=V(v),b=$===v,x=i||(b||!g?[Se(v)]:gn(v)),w=[v].concat(x).reduce(function(oe,X){return oe.concat(V(X)===Ke?mn(t,{placement:X,boundary:s,rootBoundary:f,padding:l,flipVariations:g,allowedAutoPlacements:h}):X)},[]),y=t.rects.reference,C=t.rects.popper,D=new Map,P=!0,E=w[0],A=0;A<w.length;A++){var O=w[A],j=V(O),S=ce(O)===ae,M=[B,H].indexOf(j)>=0,N=M?"width":"height",R=we(t,{placement:O,boundary:s,rootBoundary:f,altBoundary:m,padding:l}),L=M?S?F:I:S?H:B;y[N]>C[N]&&(L=Se(L));var ue=Se(L),K=[];if(a&&K.push(R[j]<=0),c&&K.push(R[L]<=0,R[ue]<=0),K.every(function(oe){return oe})){E=O,P=!1;break}D.set(O,K)}if(P)for(var T=g?3:1,ne=function(X){var fe=w.find(function(Oe){var J=D.get(Oe);if(J)return J.slice(0,X).every(function(Re){return Re})});if(fe)return E=fe,"break"},le=T;le>0;le--){var $e=ne(le);if($e==="break")break}t.placement!==E&&(t.modifiersData[n]._skip=!0,t.placement=E,t.reset=!0)}}const wn={name:"flip",enabled:!0,phase:"main",fn:hn,requiresIfExists:["offset"],data:{_skip:!1}};function mt(e,t,r){return r===void 0&&(r={x:0,y:0}),{top:e.top-t.height-r.y,right:e.right-t.width+r.x,bottom:e.bottom-t.height+r.y,left:e.left-t.width-r.x}}function gt(e){return[B,F,H,I].some(function(t){return e[t]>=0})}function yn(e){var t=e.state,r=e.name,n=t.rects.reference,o=t.rects.popper,a=t.modifiersData.preventOverflow,u=we(t,{elementContext:"reference"}),c=we(t,{altBoundary:!0}),i=mt(u,n),l=mt(c,o,a),s=gt(i),f=gt(l);t.modifiersData[r]={referenceClippingOffsets:i,popperEscapeOffsets:l,isReferenceHidden:s,hasPopperEscaped:f},t.attributes.popper=Object.assign({},t.attributes.popper,{"data-popper-reference-hidden":s,"data-popper-escaped":f})}const bn={name:"hide",enabled:!0,phase:"main",requiresIfExists:["preventOverflow"],fn:yn};function xn(e,t,r){var n=V(e),o=[I,B].indexOf(n)>=0?-1:1,a=typeof r=="function"?r(Object.assign({},t,{placement:e})):r,u=a[0],c=a[1];return u=u||0,c=(c||0)*o,[I,F].indexOf(n)>=0?{x:c,y:u}:{x:u,y:c}}function $n(e){var t=e.state,r=e.options,n=e.name,o=r.offset,a=o===void 0?[0,0]:o,u=St.reduce(function(s,f){return s[f]=xn(f,t.rects,a),s},{}),c=u[t.placement],i=c.x,l=c.y;t.modifiersData.popperOffsets!=null&&(t.modifiersData.popperOffsets.x+=i,t.modifiersData.popperOffsets.y+=l),t.modifiersData[n]=u}const On={name:"offset",enabled:!0,phase:"main",requires:["popperOffsets"],fn:$n};function Cn(e){var t=e.state,r=e.name;t.modifiersData[r]=Nt({reference:t.rects.reference,element:t.rects.popper,strategy:"absolute",placement:t.placement})}const Dn={name:"popperOffsets",enabled:!0,phase:"read",fn:Cn,data:{}};function jn(e){return e==="x"?"y":"x"}function Pn(e){var t=e.state,r=e.options,n=e.name,o=r.mainAxis,a=o===void 0?!0:o,u=r.altAxis,c=u===void 0?!1:u,i=r.boundary,l=r.rootBoundary,s=r.altBoundary,f=r.padding,m=r.tether,p=m===void 0?!0:m,g=r.tetherOffset,h=g===void 0?0:g,v=we(t,{boundary:i,rootBoundary:l,padding:f,altBoundary:s}),$=V(t.placement),b=ce(t.placement),x=!b,w=qe($),y=jn(w),C=t.modifiersData.popperOffsets,D=t.rects.reference,P=t.rects.popper,E=typeof h=="function"?h(Object.assign({},t.rects,{placement:t.placement})):h,A=typeof E=="number"?{mainAxis:E,altAxis:E}:Object.assign({mainAxis:0,altAxis:0},E),O=t.modifiersData.offset?t.modifiersData.offset[t.placement]:null,j={x:0,y:0};if(C){if(a){var S,M=w==="y"?B:I,N=w==="y"?H:F,R=w==="y"?"height":"width",L=C[w],ue=L+v[M],K=L-v[N],T=p?-P[R]/2:0,ne=b===ae?D[R]:P[R],le=b===ae?-P[R]:-D[R],$e=t.elements.arrow,oe=p&&$e?Ue($e):{width:0,height:0},X=t.modifiersData["arrow#persistent"]?t.modifiersData["arrow#persistent"].padding:kt(),fe=X[M],Oe=X[N],J=me(0,D[R],oe[R]),Re=x?D[R]/2-T-J-fe-A.mainAxis:ne-J-fe-A.mainAxis,or=x?-D[R]/2+T+J+Oe+A.mainAxis:le+J+Oe+A.mainAxis,Te=t.elements.arrow&&be(t.elements.arrow),ar=Te?w==="y"?Te.clientTop||0:Te.clientLeft||0:0,Je=(S=O==null?void 0:O[w])!=null?S:0,ir=L+Re-Je-ar,sr=L+or-Je,Qe=me(p?Ae(ue,ir):ue,L,p?Z(K,sr):K);C[w]=Qe,j[w]=Qe-L}if(c){var Ze,cr=w==="x"?B:I,ur=w==="x"?H:F,Q=C[y],Ce=y==="y"?"height":"width",_e=Q+v[cr],et=Q-v[ur],Ne=[B,I].indexOf($)!==-1,tt=(Ze=O==null?void 0:O[y])!=null?Ze:0,rt=Ne?_e:Q-D[Ce]-P[Ce]-tt+A.altAxis,nt=Ne?Q+D[Ce]+P[Ce]-tt-A.altAxis:et,ot=p&&Ne?Jr(rt,Q,nt):me(p?rt:_e,Q,p?nt:et);C[y]=ot,j[y]=ot-Q}t.modifiersData[n]=j}}const Sn={name:"preventOverflow",enabled:!0,phase:"main",fn:Pn,requiresIfExists:["offset"]};function An(e){return{scrollLeft:e.scrollLeft,scrollTop:e.scrollTop}}function En(e){return e===W(e)||!U(e)?ze(e):An(e)}function kn(e){var t=e.getBoundingClientRect(),r=ie(t.width)/e.offsetWidth||1,n=ie(t.height)/e.offsetHeight||1;return r!==1||n!==1}function Mn(e,t,r){r===void 0&&(r=!1);var n=U(t),o=U(t)&&kn(t),a=G(t),u=se(e,o,r),c={scrollLeft:0,scrollTop:0},i={x:0,y:0};return(n||!n&&!r)&&((Y(t)!=="body"||Ye(a))&&(c=En(t)),U(t)?(i=se(t,!0),i.x+=t.clientLeft,i.y+=t.clientTop):a&&(i.x=Xe(a))),{x:u.left+c.scrollLeft-i.x,y:u.top+c.scrollTop-i.y,width:u.width,height:u.height}}function Rn(e){var t=new Map,r=new Set,n=[];e.forEach(function(a){t.set(a.name,a)});function o(a){r.add(a.name);var u=[].concat(a.requires||[],a.requiresIfExists||[]);u.forEach(function(c){if(!r.has(c)){var i=t.get(c);i&&o(i)}}),n.push(a)}return e.forEach(function(a){r.has(a.name)||o(a)}),n}function Tn(e){var t=Rn(e);return Xr.reduce(function(r,n){return r.concat(t.filter(function(o){return o.phase===n}))},[])}function Nn(e){var t;return function(){return t||(t=new Promise(function(r){Promise.resolve().then(function(){t=void 0,r(e())})})),t}}function Bn(e){var t=e.reduce(function(r,n){var o=r[n.name];return r[n.name]=o?Object.assign({},o,n,{options:Object.assign({},o.options,n.options),data:Object.assign({},o.data,n.data)}):n,r},{});return Object.keys(t).map(function(r){return t[r]})}var ht={placement:"bottom",modifiers:[],strategy:"absolute"};function wt(){for(var e=arguments.length,t=new Array(e),r=0;r<e;r++)t[r]=arguments[r];return!t.some(function(n){return!(n&&typeof n.getBoundingClientRect=="function")})}function In(e){e===void 0&&(e={});var t=e,r=t.defaultModifiers,n=r===void 0?[]:r,o=t.defaultOptions,a=o===void 0?ht:o;return function(c,i,l){l===void 0&&(l=a);var s={placement:"bottom",orderedModifiers:[],options:Object.assign({},ht,a),modifiersData:{},elements:{reference:c,popper:i},attributes:{},styles:{}},f=[],m=!1,p={state:s,setOptions:function($){var b=typeof $=="function"?$(s.options):$;h(),s.options=Object.assign({},a,s.options,b),s.scrollParents={reference:ee(c)?ge(c):c.contextElement?ge(c.contextElement):[],popper:ge(i)};var x=Tn(Bn([].concat(n,s.options.modifiers)));return s.orderedModifiers=x.filter(function(w){return w.enabled}),g(),p.update()},forceUpdate:function(){if(!m){var $=s.elements,b=$.reference,x=$.popper;if(wt(b,x)){s.rects={reference:Mn(b,be(x),s.options.strategy==="fixed"),popper:Ue(x)},s.reset=!1,s.placement=s.options.placement,s.orderedModifiers.forEach(function(A){return s.modifiersData[A.name]=Object.assign({},A.data)});for(var w=0;w<s.orderedModifiers.length;w++){if(s.reset===!0){s.reset=!1,w=-1;continue}var y=s.orderedModifiers[w],C=y.fn,D=y.options,P=D===void 0?{}:D,E=y.name;typeof C=="function"&&(s=C({state:s,options:P,name:E,instance:p})||s)}}}},update:Nn(function(){return new Promise(function(v){p.forceUpdate(),v(s)})}),destroy:function(){h(),m=!0}};if(!wt(c,i))return p;p.setOptions(l).then(function(v){!m&&l.onFirstUpdate&&l.onFirstUpdate(v)});function g(){s.orderedModifiers.forEach(function(v){var $=v.name,b=v.options,x=b===void 0?{}:b,w=v.effect;if(typeof w=="function"){var y=w({state:s,name:$,instance:p,options:x}),C=function(){};f.push(y||C)}})}function h(){f.forEach(function(v){return v()}),f=[]}return p}}const Ln=In({defaultModifiers:[bn,Dn,on,sn,On,wn,Sn,en]}),Wn=["enabled","placement","strategy","modifiers"];function Hn(e,t){if(e==null)return{};var r={},n=Object.keys(e),o,a;for(a=0;a<n.length;a++)o=n[a],!(t.indexOf(o)>=0)&&(r[o]=e[o]);return r}const Fn={name:"applyStyles",enabled:!1,phase:"afterWrite",fn:()=>{}},Kn={name:"ariaDescribedBy",enabled:!0,phase:"afterWrite",effect:({state:e})=>()=>{const{reference:t,popper:r}=e.elements;if("removeAttribute"in t){const n=(t.getAttribute("aria-describedby")||"").split(",").filter(o=>o.trim()!==r.id);n.length?t.setAttribute("aria-describedby",n.join(",")):t.removeAttribute("aria-describedby")}},fn:({state:e})=>{var t;const{popper:r,reference:n}=e.elements,o=(t=r.getAttribute("role"))==null?void 0:t.toLowerCase();if(r.id&&o==="tooltip"&&"setAttribute"in n){const a=n.getAttribute("aria-describedby");if(a&&a.split(",").indexOf(r.id)!==-1)return;n.setAttribute("aria-describedby",a?`${a},${r.id}`:r.id)}}},Vn=[];function Un(e,t,r={}){let{enabled:n=!0,placement:o="bottom",strategy:a="absolute",modifiers:u=Vn}=r,c=Hn(r,Wn);const i=d.useRef(u),l=d.useRef(),s=d.useCallback(()=>{var v;(v=l.current)==null||v.update()},[]),f=d.useCallback(()=>{var v;(v=l.current)==null||v.forceUpdate()},[]),[m,p]=Nr(d.useState({placement:o,update:s,forceUpdate:f,attributes:{},styles:{popper:{},arrow:{}}})),g=d.useMemo(()=>({name:"updateStateModifier",enabled:!0,phase:"write",requires:["computeStyles"],fn:({state:v})=>{const $={},b={};Object.keys(v.elements).forEach(x=>{$[x]=v.styles[x],b[x]=v.attributes[x]}),p({state:v,styles:$,attributes:b,update:s,forceUpdate:f,placement:v.placement})}}),[s,f,p]),h=d.useMemo(()=>(ve(i.current,u)||(i.current=u),i.current),[u]);return d.useEffect(()=>{!l.current||!n||l.current.setOptions({placement:o,strategy:a,modifiers:[...h,g,Fn]})},[a,o,g,n,h]),d.useEffect(()=>{if(!(!n||e==null||t==null))return l.current=Ln(e,t,Object.assign({},c,{placement:o,strategy:a,modifiers:[...h,Kn,g]})),()=>{l.current!=null&&(l.current.destroy(),l.current=void 0,p(v=>Object.assign({},v,{attributes:{},styles:{popper:{}}})))}},[n,e,t]),m}var qn=function(){},zn=qn;const Xn=lr(zn),yt=()=>{};function Yn(e){return e.button===0}function Gn(e){return!!(e.metaKey||e.altKey||e.ctrlKey||e.shiftKey)}const Be=e=>e&&("current"in e?e.current:e),bt={click:"mousedown",mouseup:"mousedown",pointerup:"pointerdown"};function Jn(e,t=yt,{disabled:r,clickTrigger:n="click"}={}){const o=d.useRef(!1),a=d.useRef(!1),u=d.useCallback(l=>{const s=Be(e);Xn(!!s,"ClickOutside captured a close event but does not have a ref to compare it to. useClickOutside(), should be passed a ref that resolves to a DOM node"),o.current=!s||Gn(l)||!Yn(l)||!!at(s,l.target)||a.current,a.current=!1},[e]),c=q(l=>{const s=Be(e);s&&at(s,l.target)&&(a.current=!0)}),i=q(l=>{o.current||t(l)});d.useEffect(()=>{var l,s;if(r||e==null)return;const f=vr(Be(e)),m=f.defaultView||window;let p=(l=m.event)!=null?l:(s=m.parent)==null?void 0:s.event,g=null;bt[n]&&(g=De(f,bt[n],c,!0));const h=De(f,n,u,!0),v=De(f,n,b=>{if(b===p){p=void 0;return}i(b)});let $=[];return"ontouchstart"in f.documentElement&&($=[].slice.call(f.body.children).map(b=>De(b,"mousemove",yt))),()=>{g==null||g(),h(),v(),$.forEach(b=>b())}},[e,r,n,u,c,i])}function Qn(e){const t={};return Array.isArray(e)?(e==null||e.forEach(r=>{t[r.name]=r}),t):e||t}function Zn(e={}){return Array.isArray(e)?e:Object.keys(e).map(t=>(e[t].name=t,e[t]))}function _n({enabled:e,enableEvents:t,placement:r,flip:n,offset:o,fixed:a,containerPadding:u,arrowElement:c,popperConfig:i={}}){var l,s,f,m,p;const g=Qn(i.modifiers);return Object.assign({},i,{placement:r,enabled:e,strategy:a?"fixed":i.strategy,modifiers:Zn(Object.assign({},g,{eventListeners:{enabled:t,options:(l=g.eventListeners)==null?void 0:l.options},preventOverflow:Object.assign({},g.preventOverflow,{options:u?Object.assign({padding:u},(s=g.preventOverflow)==null?void 0:s.options):(f=g.preventOverflow)==null?void 0:f.options}),offset:{options:Object.assign({offset:o},(m=g.offset)==null?void 0:m.options)},arrow:Object.assign({},g.arrow,{enabled:!!c,options:Object.assign({},(p=g.arrow)==null?void 0:p.options,{element:c})}),flip:Object.assign({enabled:!!n},g.flip)}))})}const eo=["children"];function to(e,t){if(e==null)return{};var r={},n=Object.keys(e),o,a;for(a=0;a<n.length;a++)o=n[a],!(t.indexOf(o)>=0)&&(r[o]=e[o]);return r}const ro=()=>{};function Bt(e={}){const t=d.useContext(ke),[r,n]=mr(),o=d.useRef(!1),{flip:a,offset:u,rootCloseEvent:c,fixed:i=!1,placement:l,popperConfig:s={},enableEventListeners:f=!0,usePopper:m=!!t}=e,p=(t==null?void 0:t.show)==null?!!e.show:t.show;p&&!o.current&&(o.current=!0);const g=C=>{t==null||t.toggle(!1,C)},{placement:h,setMenu:v,menuElement:$,toggleElement:b}=t||{},x=Un(b,$,_n({placement:l||h||"bottom-start",enabled:m,enableEvents:f??p,offset:u,flip:a,fixed:i,arrowElement:r,popperConfig:s})),w=Object.assign({ref:v||ro,"aria-labelledby":b==null?void 0:b.id},x.attributes.popper,{style:x.styles.popper}),y={show:p,placement:h,hasShown:o.current,toggle:t==null?void 0:t.toggle,popper:m?x:null,arrowProps:m?Object.assign({ref:n},x.attributes.arrow,{style:x.styles.arrow}):{}};return Jn($,g,{clickTrigger:c,disabled:!p}),[w,y]}const no={usePopper:!0};function Ge(e){let{children:t}=e,r=to(e,eo);const[n,o]=Bt(r);return k.jsx(k.Fragment,{children:t(n,o)})}Ge.displayName="DropdownMenu";Ge.defaultProps=no;const Ee={prefix:String(Math.round(Math.random()*1e10)),current:0},It=_.createContext(Ee),oo=_.createContext(!1);let ao=!!(typeof window<"u"&&window.document&&window.document.createElement),Ie=new WeakMap;function io(e=!1){let t=d.useContext(It),r=d.useRef(null);if(r.current===null&&!e){var n,o;let a=(o=_.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED)===null||o===void 0||(n=o.ReactCurrentOwner)===null||n===void 0?void 0:n.current;if(a){let u=Ie.get(a);u==null?Ie.set(a,{id:t.current,state:a.memoizedState}):a.memoizedState!==u.state&&(t.current=u.id,Ie.delete(a))}r.current=++t.current}return r.current}function so(e){let t=d.useContext(It);t===Ee&&!ao&&console.warn("When server rendering, you must wrap your application in an <SSRProvider> to ensure consistent ids are generated between the client and server.");let r=io(!!e),n=`react-aria${t.prefix}`;return e||`${n}-${r}`}function co(e){let t=_.useId(),[r]=d.useState(vo()),n=r?"react-aria":`react-aria${Ee.prefix}`;return e||`${n}-${t}`}const uo=typeof _.useId=="function"?co:so;function lo(){return!1}function fo(){return!0}function po(e){return()=>{}}function vo(){return typeof _.useSyncExternalStore=="function"?_.useSyncExternalStore(po,lo,fo):d.useContext(oo)}const Lt=e=>{var t;return((t=e.getAttribute("role"))==null?void 0:t.toLowerCase())==="menu"},xt=()=>{};function Wt(){const e=uo(),{show:t=!1,toggle:r=xt,setToggle:n,menuElement:o}=d.useContext(ke)||{},a=d.useCallback(c=>{r(!t,c)},[t,r]),u={id:e,ref:n||xt,onClick:a,"aria-expanded":!!t};return o&&Lt(o)&&(u["aria-haspopup"]=!0),[u,{show:t,toggle:r}]}function Ht({children:e}){const[t,r]=Wt();return k.jsx(k.Fragment,{children:e(t,r)})}Ht.displayName="DropdownToggle";const mo=d.createContext(null),$t=(e,t=null)=>e!=null?String(e):t||null,Fe=mo,Ft=d.createContext(null);Ft.displayName="NavContext";const go=Ft,ho=["eventKey","disabled","onClick","active","as"];function wo(e,t){if(e==null)return{};var r={},n=Object.keys(e),o,a;for(a=0;a<n.length;a++)o=n[a],!(t.indexOf(o)>=0)&&(r[o]=e[o]);return r}function Kt({key:e,href:t,active:r,disabled:n,onClick:o}){const a=d.useContext(Fe),u=d.useContext(go),{activeKey:c}=u||{},i=$t(e,t),l=r==null&&e!=null?$t(c)===i:r;return[{onClick:q(f=>{n||(o==null||o(f),a&&!f.isPropagationStopped()&&a(i,f))}),"aria-disabled":n||void 0,"aria-selected":l,[Ct("dropdown-item")]:""},{isActive:l}]}const Vt=d.forwardRef((e,t)=>{let{eventKey:r,disabled:n,onClick:o,active:a,as:u=xr}=e,c=wo(e,ho);const[i]=Kt({key:r,href:c.href,disabled:n,onClick:o,active:a});return k.jsx(u,Object.assign({},c,{ref:t},i))});Vt.displayName="DropdownItem";function Ot(){const e=Rr(),t=d.useRef(null),r=d.useCallback(n=>{t.current=n,e()},[e]);return[t,r]}function xe({defaultShow:e,show:t,onSelect:r,onToggle:n,itemSelector:o=`* [${Ct("dropdown-item")}]`,focusFirstItemOnShow:a,placement:u="bottom-start",children:c}){const i=gr(),[l,s]=Mr(t,e,n),[f,m]=Ot(),p=f.current,[g,h]=Ot(),v=g.current,$=hr(l),b=d.useRef(null),x=d.useRef(!1),w=d.useContext(Fe),y=d.useCallback((O,j,S=j==null?void 0:j.type)=>{s(O,{originalEvent:j,source:S})},[s]),C=q((O,j)=>{r==null||r(O,j),y(!1,j,"select"),j.isPropagationStopped()||w==null||w(O,j)}),D=d.useMemo(()=>({toggle:y,placement:u,show:l,menuElement:p,toggleElement:v,setMenu:m,setToggle:h}),[y,u,l,p,v,m,h]);p&&$&&!l&&(x.current=p.contains(p.ownerDocument.activeElement));const P=q(()=>{v&&v.focus&&v.focus()}),E=q(()=>{const O=b.current;let j=a;if(j==null&&(j=f.current&&Lt(f.current)?"keyboard":!1),j===!1||j==="keyboard"&&!/^key.+$/.test(O))return;const S=it(f.current,o)[0];S&&S.focus&&S.focus()});d.useEffect(()=>{l?E():x.current&&(x.current=!1,P())},[l,x,P,E]),d.useEffect(()=>{b.current=null});const A=(O,j)=>{if(!f.current)return null;const S=it(f.current,o);let M=S.indexOf(O)+j;return M=Math.max(0,Math.min(M,S.length)),S[M]};return Pr(d.useCallback(()=>i.document,[i]),"keydown",O=>{var j,S;const{key:M}=O,N=O.target,R=(j=f.current)==null?void 0:j.contains(N),L=(S=g.current)==null?void 0:S.contains(N);if(/input|textarea/i.test(N.tagName)&&(M===" "||M!=="Escape"&&R||M==="Escape"&&N.type==="search")||!R&&!L||M==="Tab"&&(!f.current||!l))return;b.current=O.type;const K={originalEvent:O,source:O.type};switch(M){case"ArrowUp":{const T=A(N,-1);T&&T.focus&&T.focus(),O.preventDefault();return}case"ArrowDown":if(O.preventDefault(),!l)s(!0,K);else{const T=A(N,1);T&&T.focus&&T.focus()}return;case"Tab":wr(N.ownerDocument,"keyup",T=>{var ne;(T.key==="Tab"&&!T.target||!((ne=f.current)!=null&&ne.contains(T.target)))&&s(!1,K)},{once:!0});break;case"Escape":M==="Escape"&&(O.preventDefault(),O.stopPropagation()),s(!1,K);break}}),k.jsx(Fe.Provider,{value:C,children:k.jsx(ke.Provider,{value:D,children:c})})}xe.displayName="Dropdown";xe.Menu=Ge;xe.Toggle=Ht;xe.Item=Vt;const Ut=d.createContext({});Ut.displayName="DropdownContext";const qt=Ut,zt=d.forwardRef(({className:e,bsPrefix:t,as:r="hr",role:n="separator",...o},a)=>(t=te(t,"dropdown-divider"),k.jsx(r,{ref:a,className:re(e,t),role:n,...o})));zt.displayName="DropdownDivider";const yo=zt,Xt=d.forwardRef(({className:e,bsPrefix:t,as:r="div",role:n="heading",...o},a)=>(t=te(t,"dropdown-header"),k.jsx(r,{ref:a,className:re(e,t),role:n,...o})));Xt.displayName="DropdownHeader";const bo=Xt,Yt=d.forwardRef(({bsPrefix:e,className:t,eventKey:r,disabled:n=!1,onClick:o,active:a,as:u=kr,...c},i)=>{const l=te(e,"dropdown-item"),[s,f]=Kt({key:r,href:c.href,disabled:n,onClick:o,active:a});return k.jsx(u,{...c,...s,ref:i,className:re(t,l,f.isActive&&"active",n&&"disabled")})});Yt.displayName="DropdownItem";const xo=Yt,Gt=d.forwardRef(({className:e,bsPrefix:t,as:r="span",...n},o)=>(t=te(t,"dropdown-item-text"),k.jsx(r,{ref:o,className:re(e,t),...n})));Gt.displayName="DropdownItemText";const $o=Gt,Jt=d.createContext(null);Jt.displayName="InputGroupContext";const Qt=Jt,Zt=d.createContext(null);Zt.displayName="NavbarContext";const Oo=Zt;function _t(e,t){return e}function er(e,t,r){const n=r?"top-end":"top-start",o=r?"top-start":"top-end",a=r?"bottom-end":"bottom-start",u=r?"bottom-start":"bottom-end",c=r?"right-start":"left-start",i=r?"right-end":"left-end",l=r?"left-start":"right-start",s=r?"left-end":"right-end";let f=e?u:a;return t==="up"?f=e?o:n:t==="end"?f=e?s:l:t==="start"?f=e?i:c:t==="down-centered"?f="bottom":t==="up-centered"&&(f="top"),f}const tr=d.forwardRef(({bsPrefix:e,className:t,align:r,rootCloseEvent:n,flip:o=!0,show:a,renderOnMount:u,as:c="div",popperConfig:i,variant:l,...s},f)=>{let m=!1;const p=d.useContext(Oo),g=te(e,"dropdown-menu"),{align:h,drop:v,isRTL:$}=d.useContext(qt);r=r||h;const b=d.useContext(Qt),x=[];if(r)if(typeof r=="object"){const O=Object.keys(r);if(O.length){const j=O[0],S=r[j];m=S==="start",x.push(`${g}-${j}-${S}`)}}else r==="end"&&(m=!0);const w=er(m,v,$),[y,{hasShown:C,popper:D,show:P,toggle:E}]=Bt({flip:o,rootCloseEvent:n,show:a,usePopper:!p&&x.length===0,offset:[0,2],popperConfig:i,placement:w});if(y.ref=Dt(_t(f),y.ref),yr(()=>{P&&(D==null||D.update())},[P]),!C&&!u&&!b)return null;typeof c!="string"&&(y.show=P,y.close=()=>E==null?void 0:E(!1),y.align=r);let A=s.style;return D!=null&&D.placement&&(A={...s.style,...y.style},s["x-placement"]=D.placement),k.jsx(c,{...s,...y,style:A,...(x.length||p)&&{"data-bs-popper":"static"},className:re(t,g,P&&"show",m&&`${g}-end`,l&&`${g}-${l}`,...x)})});tr.displayName="DropdownMenu";const Co=tr,rr=d.forwardRef(({bsPrefix:e,split:t,className:r,childBsPrefix:n,as:o=$r,...a},u)=>{const c=te(e,"dropdown-toggle"),i=d.useContext(ke);n!==void 0&&(a.bsPrefix=n);const[l]=Wt();return l.ref=Dt(l.ref,_t(u)),k.jsx(o,{className:re(r,c,t&&`${c}-split`,(i==null?void 0:i.show)&&"show"),...l,...a})});rr.displayName="DropdownToggle";const Do=rr,nr=d.forwardRef((e,t)=>{const{bsPrefix:r,drop:n="down",show:o,className:a,align:u="start",onSelect:c,onToggle:i,focusFirstItemOnShow:l,as:s="div",navbar:f,autoClose:m=!0,...p}=jr(e,{show:"onToggle"}),g=d.useContext(Qt),h=te(r,"dropdown"),v=fr(),$=D=>m===!1?D==="click":m==="inside"?D!=="rootClose":m==="outside"?D!=="select":!0,b=q((D,P)=>{P.originalEvent.currentTarget===document&&(P.source!=="keydown"||P.originalEvent.key==="Escape")&&(P.source="rootClose"),$(P.source)&&(i==null||i(D,P))}),w=er(u==="end",n,v),y=d.useMemo(()=>({align:u,drop:n,isRTL:v}),[u,n,v]),C={down:h,"down-centered":`${h}-center`,up:"dropup","up-centered":"dropup-center dropup",end:"dropend",start:"dropstart"};return k.jsx(qt.Provider,{value:y,children:k.jsx(xe,{placement:w,show:o,onSelect:c,onToggle:b,focusFirstItemOnShow:l,itemSelector:`.${h}-item:not(.disabled):not(:disabled)`,children:g?p.children:k.jsx(s,{...p,ref:t,className:re(a,o&&"show",C[n])})})})});nr.displayName="Dropdown";const Pe=Object.assign(nr,{Toggle:Do,Menu:Co,Item:xo,ItemText:$o,Divider:yo,Header:bo}),jo="_categories_keasm_1",Po="_active_keasm_9",So="_menu_keasm_15",de={categories:jo,"category-item":"_category-item_keasm_6",active:Po,menu:So};function Mo(e){const[t,r]=d.useState(e.default),n=o=>{var u;o.preventDefault();const a=o.target;r(a.textContent),(u=e.onSelect)==null||u.call(e,a.textContent)};return k.jsxs(Pe,{className:`${de.dropdown} ${e.className??""}`,children:[k.jsxs(Pe.Toggle,{className:de.categories,children:[e.title&&`${e.title}: `,t]}),k.jsx(Pe.Menu,{className:`dropdown-menu ${de.menu}`,children:e.categories.map(o=>k.jsx(Pe.Item,{className:`${de["category-item"]} ${t.toLowerCase()===o.toLowerCase()?de.active:""}`,as:"button",onClick:n,children:o},`category_${o}`))})]})}export{Mo as D,Qt as I};
