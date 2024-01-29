import{_ as Et,b as De,a as Pt,d as Xe,o as Dt,l as ge}from"./useWindow-ee83e482.js";import{r as P,j as Ye,p as Rt}from"./index-a92a2e79.js";import{u as $t}from"./Button-58481d39.js";function Re(){return Re=Object.assign?Object.assign.bind():function(e){for(var t=1;t<arguments.length;t++){var r=arguments[t];for(var n in r)Object.prototype.hasOwnProperty.call(r,n)&&(e[n]=r[n])}return e},Re.apply(this,arguments)}function _e(e){return"default"+e.charAt(0).toUpperCase()+e.substr(1)}function Ct(e){var t=Mt(e,"string");return typeof t=="symbol"?t:String(t)}function Mt(e,t){if(typeof e!="object"||e===null)return e;var r=e[Symbol.toPrimitive];if(r!==void 0){var n=r.call(e,t||"default");if(typeof n!="object")return n;throw new TypeError("@@toPrimitive must return a primitive value.")}return(t==="string"?String:Number)(e)}function St(e,t,r){var n=P.useRef(e!==void 0),i=P.useState(t),o=i[0],c=i[1],f=e!==void 0,s=n.current;return n.current=f,!f&&s&&o!==t&&c(t),[f?e:o,P.useCallback(function(u){for(var a=arguments.length,l=new Array(a>1?a-1:0),m=1;m<a;m++)l[m-1]=arguments[m];r&&r.apply(void 0,[u].concat(l)),c(u)},[r])]}function en(e,t){return Object.keys(t).reduce(function(r,n){var i,o=r,c=o[_e(n)],f=o[n],s=Et(o,[_e(n),n].map(Ct)),u=t[n],a=St(f,c,e[u]),l=a[0],m=a[1];return Re({},s,(i={},i[n]=l,i[u]=m,i))},e)}const Lt=["onKeyDown"];function Bt(e,t){if(e==null)return{};var r={},n=Object.keys(e),i,o;for(o=0;o<n.length;o++)i=n[o],!(t.indexOf(i)>=0)&&(r[i]=e[i]);return r}function Tt(e){return!e||e.trim()==="#"}const ut=P.forwardRef((e,t)=>{let{onKeyDown:r}=e,n=Bt(e,Lt);const[i]=$t(Object.assign({tagName:"a"},n)),o=De(c=>{i.onKeyDown(c),r==null||r(c)});return Tt(n.href)||n.role==="button"?Ye.jsx("a",Object.assign({ref:t},n,i,{onKeyDown:o})):Ye.jsx("a",Object.assign({ref:t},n,{onKeyDown:r}))});ut.displayName="Anchor";const tn=ut;var Ge=Object.prototype.hasOwnProperty;function Je(e,t,r){for(r of e.keys())if(oe(r,t))return r}function oe(e,t){var r,n,i;if(e===t)return!0;if(e&&t&&(r=e.constructor)===t.constructor){if(r===Date)return e.getTime()===t.getTime();if(r===RegExp)return e.toString()===t.toString();if(r===Array){if((n=e.length)===t.length)for(;n--&&oe(e[n],t[n]););return n===-1}if(r===Set){if(e.size!==t.size)return!1;for(n of e)if(i=n,i&&typeof i=="object"&&(i=Je(t,i),!i)||!t.has(i))return!1;return!0}if(r===Map){if(e.size!==t.size)return!1;for(n of e)if(i=n[0],i&&typeof i=="object"&&(i=Je(t,i),!i)||!oe(n[1],t.get(i)))return!1;return!0}if(r===ArrayBuffer)e=new Uint8Array(e),t=new Uint8Array(t);else if(r===DataView){if((n=e.byteLength)===t.byteLength)for(;n--&&e.getInt8(n)===t.getInt8(n););return n===-1}if(ArrayBuffer.isView(e)){if((n=e.byteLength)===t.byteLength)for(;n--&&e[n]===t[n];);return n===-1}if(!r||typeof e=="object"){n=0;for(r in e)if(Ge.call(e,r)&&++n&&!Ge.call(t,r)||!(r in t)||!oe(e[r],t[r]))return!1;return Object.keys(t).length===n}}return e!==e&&t!==t}function kt(e){const t=Pt();return[e[0],P.useCallback(r=>{if(t())return e[1](r)},[t,e[1]])]}var C="top",B="bottom",T="right",M="left",Me="auto",ce=[C,B,T,M],Q="start",fe="end",Wt="clippingParents",ct="viewport",ie="popper",Ht="reference",Qe=ce.reduce(function(e,t){return e.concat([t+"-"+Q,t+"-"+fe])},[]),pt=[].concat(ce,[Me]).reduce(function(e,t){return e.concat([t,t+"-"+Q,t+"-"+fe])},[]),It="beforeRead",Vt="read",Ft="afterRead",Ut="beforeMain",Kt="main",Nt="afterMain",qt="beforeWrite",zt="write",Xt="afterWrite",Yt=[It,Vt,Ft,Ut,Kt,Nt,qt,zt,Xt];function H(e){return e.split("-")[0]}function L(e){if(e==null)return window;if(e.toString()!=="[object Window]"){var t=e.ownerDocument;return t&&t.defaultView||window}return e}function G(e){var t=L(e).Element;return e instanceof t||e instanceof Element}function I(e){var t=L(e).HTMLElement;return e instanceof t||e instanceof HTMLElement}function Se(e){if(typeof ShadowRoot>"u")return!1;var t=L(e).ShadowRoot;return e instanceof t||e instanceof ShadowRoot}var _=Math.max,we=Math.min,Z=Math.round;function $e(){var e=navigator.userAgentData;return e!=null&&e.brands&&Array.isArray(e.brands)?e.brands.map(function(t){return t.brand+"/"+t.version}).join(" "):navigator.userAgent}function lt(){return!/^((?!chrome|android).)*safari/i.test($e())}function ee(e,t,r){t===void 0&&(t=!1),r===void 0&&(r=!1);var n=e.getBoundingClientRect(),i=1,o=1;t&&I(e)&&(i=e.offsetWidth>0&&Z(n.width)/e.offsetWidth||1,o=e.offsetHeight>0&&Z(n.height)/e.offsetHeight||1);var c=G(e)?L(e):window,f=c.visualViewport,s=!lt()&&r,u=(n.left+(s&&f?f.offsetLeft:0))/i,a=(n.top+(s&&f?f.offsetTop:0))/o,l=n.width/i,m=n.height/o;return{width:l,height:m,top:a,right:u+l,bottom:a+m,left:u,x:u,y:a}}function Le(e){var t=ee(e),r=e.offsetWidth,n=e.offsetHeight;return Math.abs(t.width-r)<=1&&(r=t.width),Math.abs(t.height-n)<=1&&(n=t.height),{x:e.offsetLeft,y:e.offsetTop,width:r,height:n}}function dt(e,t){var r=t.getRootNode&&t.getRootNode();if(e.contains(t))return!0;if(r&&Se(r)){var n=t;do{if(n&&e.isSameNode(n))return!0;n=n.parentNode||n.host}while(n)}return!1}function U(e){return e?(e.nodeName||"").toLowerCase():null}function V(e){return L(e).getComputedStyle(e)}function _t(e){return["table","td","th"].indexOf(U(e))>=0}function K(e){return((G(e)?e.ownerDocument:e.document)||window.document).documentElement}function Oe(e){return U(e)==="html"?e:e.assignedSlot||e.parentNode||(Se(e)?e.host:null)||K(e)}function Ze(e){return!I(e)||V(e).position==="fixed"?null:e.offsetParent}function Gt(e){var t=/firefox/i.test($e()),r=/Trident/i.test($e());if(r&&I(e)){var n=V(e);if(n.position==="fixed")return null}var i=Oe(e);for(Se(i)&&(i=i.host);I(i)&&["html","body"].indexOf(U(i))<0;){var o=V(i);if(o.transform!=="none"||o.perspective!=="none"||o.contain==="paint"||["transform","perspective"].indexOf(o.willChange)!==-1||t&&o.willChange==="filter"||t&&o.filter&&o.filter!=="none")return i;i=i.parentNode}return null}function pe(e){for(var t=L(e),r=Ze(e);r&&_t(r)&&V(r).position==="static";)r=Ze(r);return r&&(U(r)==="html"||U(r)==="body"&&V(r).position==="static")?t:r||Gt(e)||t}function Be(e){return["top","bottom"].indexOf(e)>=0?"x":"y"}function ae(e,t,r){return _(e,we(t,r))}function Jt(e,t,r){var n=ae(e,t,r);return n>r?r:n}function vt(){return{top:0,right:0,bottom:0,left:0}}function mt(e){return Object.assign({},vt(),e)}function ht(e,t){return t.reduce(function(r,n){return r[n]=e,r},{})}var Qt=function(t,r){return t=typeof t=="function"?t(Object.assign({},r.rects,{placement:r.placement})):t,mt(typeof t!="number"?t:ht(t,ce))};function Zt(e){var t,r=e.state,n=e.name,i=e.options,o=r.elements.arrow,c=r.modifiersData.popperOffsets,f=H(r.placement),s=Be(f),u=[M,T].indexOf(f)>=0,a=u?"height":"width";if(!(!o||!c)){var l=Qt(i.padding,r),m=Le(o),p=s==="y"?C:M,v=s==="y"?B:T,h=r.rects.reference[a]+r.rects.reference[s]-c[s]-r.rects.popper[a],d=c[s]-r.rects.reference[s],y=pe(o),b=y?s==="y"?y.clientHeight||0:y.clientWidth||0:0,x=h/2-d/2,g=l[p],w=b-m[a]-l[v],O=b/2-m[a]/2+x,A=ae(g,O,w),D=s;r.modifiersData[n]=(t={},t[D]=A,t.centerOffset=A-O,t)}}function er(e){var t=e.state,r=e.options,n=r.element,i=n===void 0?"[data-popper-arrow]":n;i!=null&&(typeof i=="string"&&(i=t.elements.popper.querySelector(i),!i)||dt(t.elements.popper,i)&&(t.elements.arrow=i))}const tr={name:"arrow",enabled:!0,phase:"main",fn:Zt,effect:er,requires:["popperOffsets"],requiresIfExists:["preventOverflow"]};function te(e){return e.split("-")[1]}var rr={top:"auto",right:"auto",bottom:"auto",left:"auto"};function nr(e,t){var r=e.x,n=e.y,i=t.devicePixelRatio||1;return{x:Z(r*i)/i||0,y:Z(n*i)/i||0}}function et(e){var t,r=e.popper,n=e.popperRect,i=e.placement,o=e.variation,c=e.offsets,f=e.position,s=e.gpuAcceleration,u=e.adaptive,a=e.roundOffsets,l=e.isFixed,m=c.x,p=m===void 0?0:m,v=c.y,h=v===void 0?0:v,d=typeof a=="function"?a({x:p,y:h}):{x:p,y:h};p=d.x,h=d.y;var y=c.hasOwnProperty("x"),b=c.hasOwnProperty("y"),x=M,g=C,w=window;if(u){var O=pe(r),A="clientHeight",D="clientWidth";if(O===L(r)&&(O=K(r),V(O).position!=="static"&&f==="absolute"&&(A="scrollHeight",D="scrollWidth")),O=O,i===C||(i===M||i===T)&&o===fe){g=B;var E=l&&O===w&&w.visualViewport?w.visualViewport.height:O[A];h-=E-n.height,h*=s?1:-1}if(i===M||(i===C||i===B)&&o===fe){x=T;var j=l&&O===w&&w.visualViewport?w.visualViewport.width:O[D];p-=j-n.width,p*=s?1:-1}}var R=Object.assign({position:f},u&&rr),k=a===!0?nr({x:p,y:h},L(r)):{x:p,y:h};if(p=k.x,h=k.y,s){var $;return Object.assign({},R,($={},$[g]=b?"0":"",$[x]=y?"0":"",$.transform=(w.devicePixelRatio||1)<=1?"translate("+p+"px, "+h+"px)":"translate3d("+p+"px, "+h+"px, 0)",$))}return Object.assign({},R,(t={},t[g]=b?h+"px":"",t[x]=y?p+"px":"",t.transform="",t))}function ir(e){var t=e.state,r=e.options,n=r.gpuAcceleration,i=n===void 0?!0:n,o=r.adaptive,c=o===void 0?!0:o,f=r.roundOffsets,s=f===void 0?!0:f,u={placement:H(t.placement),variation:te(t.placement),popper:t.elements.popper,popperRect:t.rects.popper,gpuAcceleration:i,isFixed:t.options.strategy==="fixed"};t.modifiersData.popperOffsets!=null&&(t.styles.popper=Object.assign({},t.styles.popper,et(Object.assign({},u,{offsets:t.modifiersData.popperOffsets,position:t.options.strategy,adaptive:c,roundOffsets:s})))),t.modifiersData.arrow!=null&&(t.styles.arrow=Object.assign({},t.styles.arrow,et(Object.assign({},u,{offsets:t.modifiersData.arrow,position:"absolute",adaptive:!1,roundOffsets:s})))),t.attributes.popper=Object.assign({},t.attributes.popper,{"data-popper-placement":t.placement})}const or={name:"computeStyles",enabled:!0,phase:"beforeWrite",fn:ir,data:{}};var ye={passive:!0};function ar(e){var t=e.state,r=e.instance,n=e.options,i=n.scroll,o=i===void 0?!0:i,c=n.resize,f=c===void 0?!0:c,s=L(t.elements.popper),u=[].concat(t.scrollParents.reference,t.scrollParents.popper);return o&&u.forEach(function(a){a.addEventListener("scroll",r.update,ye)}),f&&s.addEventListener("resize",r.update,ye),function(){o&&u.forEach(function(a){a.removeEventListener("scroll",r.update,ye)}),f&&s.removeEventListener("resize",r.update,ye)}}const sr={name:"eventListeners",enabled:!0,phase:"write",fn:function(){},effect:ar,data:{}};var fr={left:"right",right:"left",bottom:"top",top:"bottom"};function be(e){return e.replace(/left|right|bottom|top/g,function(t){return fr[t]})}var ur={start:"end",end:"start"};function tt(e){return e.replace(/start|end/g,function(t){return ur[t]})}function Te(e){var t=L(e),r=t.pageXOffset,n=t.pageYOffset;return{scrollLeft:r,scrollTop:n}}function ke(e){return ee(K(e)).left+Te(e).scrollLeft}function cr(e,t){var r=L(e),n=K(e),i=r.visualViewport,o=n.clientWidth,c=n.clientHeight,f=0,s=0;if(i){o=i.width,c=i.height;var u=lt();(u||!u&&t==="fixed")&&(f=i.offsetLeft,s=i.offsetTop)}return{width:o,height:c,x:f+ke(e),y:s}}function pr(e){var t,r=K(e),n=Te(e),i=(t=e.ownerDocument)==null?void 0:t.body,o=_(r.scrollWidth,r.clientWidth,i?i.scrollWidth:0,i?i.clientWidth:0),c=_(r.scrollHeight,r.clientHeight,i?i.scrollHeight:0,i?i.clientHeight:0),f=-n.scrollLeft+ke(e),s=-n.scrollTop;return V(i||r).direction==="rtl"&&(f+=_(r.clientWidth,i?i.clientWidth:0)-o),{width:o,height:c,x:f,y:s}}function We(e){var t=V(e),r=t.overflow,n=t.overflowX,i=t.overflowY;return/auto|scroll|overlay|hidden/.test(r+i+n)}function gt(e){return["html","body","#document"].indexOf(U(e))>=0?e.ownerDocument.body:I(e)&&We(e)?e:gt(Oe(e))}function se(e,t){var r;t===void 0&&(t=[]);var n=gt(e),i=n===((r=e.ownerDocument)==null?void 0:r.body),o=L(n),c=i?[o].concat(o.visualViewport||[],We(n)?n:[]):n,f=t.concat(c);return i?f:f.concat(se(Oe(c)))}function Ce(e){return Object.assign({},e,{left:e.x,top:e.y,right:e.x+e.width,bottom:e.y+e.height})}function lr(e,t){var r=ee(e,!1,t==="fixed");return r.top=r.top+e.clientTop,r.left=r.left+e.clientLeft,r.bottom=r.top+e.clientHeight,r.right=r.left+e.clientWidth,r.width=e.clientWidth,r.height=e.clientHeight,r.x=r.left,r.y=r.top,r}function rt(e,t,r){return t===ct?Ce(cr(e,r)):G(t)?lr(t,r):Ce(pr(K(e)))}function dr(e){var t=se(Oe(e)),r=["absolute","fixed"].indexOf(V(e).position)>=0,n=r&&I(e)?pe(e):e;return G(n)?t.filter(function(i){return G(i)&&dt(i,n)&&U(i)!=="body"}):[]}function vr(e,t,r,n){var i=t==="clippingParents"?dr(e):[].concat(t),o=[].concat(i,[r]),c=o[0],f=o.reduce(function(s,u){var a=rt(e,u,n);return s.top=_(a.top,s.top),s.right=we(a.right,s.right),s.bottom=we(a.bottom,s.bottom),s.left=_(a.left,s.left),s},rt(e,c,n));return f.width=f.right-f.left,f.height=f.bottom-f.top,f.x=f.left,f.y=f.top,f}function yt(e){var t=e.reference,r=e.element,n=e.placement,i=n?H(n):null,o=n?te(n):null,c=t.x+t.width/2-r.width/2,f=t.y+t.height/2-r.height/2,s;switch(i){case C:s={x:c,y:t.y-r.height};break;case B:s={x:c,y:t.y+t.height};break;case T:s={x:t.x+t.width,y:f};break;case M:s={x:t.x-r.width,y:f};break;default:s={x:t.x,y:t.y}}var u=i?Be(i):null;if(u!=null){var a=u==="y"?"height":"width";switch(o){case Q:s[u]=s[u]-(t[a]/2-r[a]/2);break;case fe:s[u]=s[u]+(t[a]/2-r[a]/2);break}}return s}function ue(e,t){t===void 0&&(t={});var r=t,n=r.placement,i=n===void 0?e.placement:n,o=r.strategy,c=o===void 0?e.strategy:o,f=r.boundary,s=f===void 0?Wt:f,u=r.rootBoundary,a=u===void 0?ct:u,l=r.elementContext,m=l===void 0?ie:l,p=r.altBoundary,v=p===void 0?!1:p,h=r.padding,d=h===void 0?0:h,y=mt(typeof d!="number"?d:ht(d,ce)),b=m===ie?Ht:ie,x=e.rects.popper,g=e.elements[v?b:m],w=vr(G(g)?g:g.contextElement||K(e.elements.popper),s,a,c),O=ee(e.elements.reference),A=yt({reference:O,element:x,strategy:"absolute",placement:i}),D=Ce(Object.assign({},x,A)),E=m===ie?D:O,j={top:w.top-E.top+y.top,bottom:E.bottom-w.bottom+y.bottom,left:w.left-E.left+y.left,right:E.right-w.right+y.right},R=e.modifiersData.offset;if(m===ie&&R){var k=R[i];Object.keys(j).forEach(function($){var N=[T,B].indexOf($)>=0?1:-1,q=[C,B].indexOf($)>=0?"y":"x";j[$]+=k[q]*N})}return j}function mr(e,t){t===void 0&&(t={});var r=t,n=r.placement,i=r.boundary,o=r.rootBoundary,c=r.padding,f=r.flipVariations,s=r.allowedAutoPlacements,u=s===void 0?pt:s,a=te(n),l=a?f?Qe:Qe.filter(function(v){return te(v)===a}):ce,m=l.filter(function(v){return u.indexOf(v)>=0});m.length===0&&(m=l);var p=m.reduce(function(v,h){return v[h]=ue(e,{placement:h,boundary:i,rootBoundary:o,padding:c})[H(h)],v},{});return Object.keys(p).sort(function(v,h){return p[v]-p[h]})}function hr(e){if(H(e)===Me)return[];var t=be(e);return[tt(e),t,tt(t)]}function gr(e){var t=e.state,r=e.options,n=e.name;if(!t.modifiersData[n]._skip){for(var i=r.mainAxis,o=i===void 0?!0:i,c=r.altAxis,f=c===void 0?!0:c,s=r.fallbackPlacements,u=r.padding,a=r.boundary,l=r.rootBoundary,m=r.altBoundary,p=r.flipVariations,v=p===void 0?!0:p,h=r.allowedAutoPlacements,d=t.options.placement,y=H(d),b=y===d,x=s||(b||!v?[be(d)]:hr(d)),g=[d].concat(x).reduce(function(J,F){return J.concat(H(F)===Me?mr(t,{placement:F,boundary:a,rootBoundary:l,padding:u,flipVariations:v,allowedAutoPlacements:h}):F)},[]),w=t.rects.reference,O=t.rects.popper,A=new Map,D=!0,E=g[0],j=0;j<g.length;j++){var R=g[j],k=H(R),$=te(R)===Q,N=[C,B].indexOf(k)>=0,q=N?"width":"height",S=ue(t,{placement:R,boundary:a,rootBoundary:l,altBoundary:m,padding:u}),W=N?$?T:M:$?B:C;w[q]>O[q]&&(W=be(W));var le=be(W),z=[];if(o&&z.push(S[k]<=0),f&&z.push(S[W]<=0,S[le]<=0),z.every(function(J){return J})){E=R,D=!1;break}A.set(R,z)}if(D)for(var de=v?3:1,xe=function(F){var ne=g.find(function(me){var X=A.get(me);if(X)return X.slice(0,F).every(function(Ae){return Ae})});if(ne)return E=ne,"break"},re=de;re>0;re--){var ve=xe(re);if(ve==="break")break}t.placement!==E&&(t.modifiersData[n]._skip=!0,t.placement=E,t.reset=!0)}}const yr={name:"flip",enabled:!0,phase:"main",fn:gr,requiresIfExists:["offset"],data:{_skip:!1}};function nt(e,t,r){return r===void 0&&(r={x:0,y:0}),{top:e.top-t.height-r.y,right:e.right-t.width+r.x,bottom:e.bottom-t.height+r.y,left:e.left-t.width-r.x}}function it(e){return[C,T,B,M].some(function(t){return e[t]>=0})}function br(e){var t=e.state,r=e.name,n=t.rects.reference,i=t.rects.popper,o=t.modifiersData.preventOverflow,c=ue(t,{elementContext:"reference"}),f=ue(t,{altBoundary:!0}),s=nt(c,n),u=nt(f,i,o),a=it(s),l=it(u);t.modifiersData[r]={referenceClippingOffsets:s,popperEscapeOffsets:u,isReferenceHidden:a,hasPopperEscaped:l},t.attributes.popper=Object.assign({},t.attributes.popper,{"data-popper-reference-hidden":a,"data-popper-escaped":l})}const wr={name:"hide",enabled:!0,phase:"main",requiresIfExists:["preventOverflow"],fn:br};function Or(e,t,r){var n=H(e),i=[M,C].indexOf(n)>=0?-1:1,o=typeof r=="function"?r(Object.assign({},t,{placement:e})):r,c=o[0],f=o[1];return c=c||0,f=(f||0)*i,[M,T].indexOf(n)>=0?{x:f,y:c}:{x:c,y:f}}function xr(e){var t=e.state,r=e.options,n=e.name,i=r.offset,o=i===void 0?[0,0]:i,c=pt.reduce(function(a,l){return a[l]=Or(l,t.rects,o),a},{}),f=c[t.placement],s=f.x,u=f.y;t.modifiersData.popperOffsets!=null&&(t.modifiersData.popperOffsets.x+=s,t.modifiersData.popperOffsets.y+=u),t.modifiersData[n]=c}const Ar={name:"offset",enabled:!0,phase:"main",requires:["popperOffsets"],fn:xr};function jr(e){var t=e.state,r=e.name;t.modifiersData[r]=yt({reference:t.rects.reference,element:t.rects.popper,strategy:"absolute",placement:t.placement})}const Er={name:"popperOffsets",enabled:!0,phase:"read",fn:jr,data:{}};function Pr(e){return e==="x"?"y":"x"}function Dr(e){var t=e.state,r=e.options,n=e.name,i=r.mainAxis,o=i===void 0?!0:i,c=r.altAxis,f=c===void 0?!1:c,s=r.boundary,u=r.rootBoundary,a=r.altBoundary,l=r.padding,m=r.tether,p=m===void 0?!0:m,v=r.tetherOffset,h=v===void 0?0:v,d=ue(t,{boundary:s,rootBoundary:u,padding:l,altBoundary:a}),y=H(t.placement),b=te(t.placement),x=!b,g=Be(y),w=Pr(g),O=t.modifiersData.popperOffsets,A=t.rects.reference,D=t.rects.popper,E=typeof h=="function"?h(Object.assign({},t.rects,{placement:t.placement})):h,j=typeof E=="number"?{mainAxis:E,altAxis:E}:Object.assign({mainAxis:0,altAxis:0},E),R=t.modifiersData.offset?t.modifiersData.offset[t.placement]:null,k={x:0,y:0};if(O){if(o){var $,N=g==="y"?C:M,q=g==="y"?B:T,S=g==="y"?"height":"width",W=O[g],le=W+d[N],z=W-d[q],de=p?-D[S]/2:0,xe=b===Q?A[S]:D[S],re=b===Q?-D[S]:-A[S],ve=t.elements.arrow,J=p&&ve?Le(ve):{width:0,height:0},F=t.modifiersData["arrow#persistent"]?t.modifiersData["arrow#persistent"].padding:vt(),ne=F[N],me=F[q],X=ae(0,A[S],J[S]),Ae=x?A[S]/2-de-X-ne-j.mainAxis:xe-X-ne-j.mainAxis,bt=x?-A[S]/2+de+X+me+j.mainAxis:re+X+me+j.mainAxis,je=t.elements.arrow&&pe(t.elements.arrow),wt=je?g==="y"?je.clientTop||0:je.clientLeft||0:0,He=($=R==null?void 0:R[g])!=null?$:0,Ot=W+Ae-He-wt,xt=W+bt-He,Ie=ae(p?we(le,Ot):le,W,p?_(z,xt):z);O[g]=Ie,k[g]=Ie-W}if(f){var Ve,At=g==="x"?C:M,jt=g==="x"?B:T,Y=O[w],he=w==="y"?"height":"width",Fe=Y+d[At],Ue=Y-d[jt],Ee=[C,M].indexOf(y)!==-1,Ke=(Ve=R==null?void 0:R[w])!=null?Ve:0,Ne=Ee?Fe:Y-A[he]-D[he]-Ke+j.altAxis,qe=Ee?Y+A[he]+D[he]-Ke-j.altAxis:Ue,ze=p&&Ee?Jt(Ne,Y,qe):ae(p?Ne:Fe,Y,p?qe:Ue);O[w]=ze,k[w]=ze-Y}t.modifiersData[n]=k}}const Rr={name:"preventOverflow",enabled:!0,phase:"main",fn:Dr,requiresIfExists:["offset"]};function $r(e){return{scrollLeft:e.scrollLeft,scrollTop:e.scrollTop}}function Cr(e){return e===L(e)||!I(e)?Te(e):$r(e)}function Mr(e){var t=e.getBoundingClientRect(),r=Z(t.width)/e.offsetWidth||1,n=Z(t.height)/e.offsetHeight||1;return r!==1||n!==1}function Sr(e,t,r){r===void 0&&(r=!1);var n=I(t),i=I(t)&&Mr(t),o=K(t),c=ee(e,i,r),f={scrollLeft:0,scrollTop:0},s={x:0,y:0};return(n||!n&&!r)&&((U(t)!=="body"||We(o))&&(f=Cr(t)),I(t)?(s=ee(t,!0),s.x+=t.clientLeft,s.y+=t.clientTop):o&&(s.x=ke(o))),{x:c.left+f.scrollLeft-s.x,y:c.top+f.scrollTop-s.y,width:c.width,height:c.height}}function Lr(e){var t=new Map,r=new Set,n=[];e.forEach(function(o){t.set(o.name,o)});function i(o){r.add(o.name);var c=[].concat(o.requires||[],o.requiresIfExists||[]);c.forEach(function(f){if(!r.has(f)){var s=t.get(f);s&&i(s)}}),n.push(o)}return e.forEach(function(o){r.has(o.name)||i(o)}),n}function Br(e){var t=Lr(e);return Yt.reduce(function(r,n){return r.concat(t.filter(function(i){return i.phase===n}))},[])}function Tr(e){var t;return function(){return t||(t=new Promise(function(r){Promise.resolve().then(function(){t=void 0,r(e())})})),t}}function kr(e){var t=e.reduce(function(r,n){var i=r[n.name];return r[n.name]=i?Object.assign({},i,n,{options:Object.assign({},i.options,n.options),data:Object.assign({},i.data,n.data)}):n,r},{});return Object.keys(t).map(function(r){return t[r]})}var ot={placement:"bottom",modifiers:[],strategy:"absolute"};function at(){for(var e=arguments.length,t=new Array(e),r=0;r<e;r++)t[r]=arguments[r];return!t.some(function(n){return!(n&&typeof n.getBoundingClientRect=="function")})}function Wr(e){e===void 0&&(e={});var t=e,r=t.defaultModifiers,n=r===void 0?[]:r,i=t.defaultOptions,o=i===void 0?ot:i;return function(f,s,u){u===void 0&&(u=o);var a={placement:"bottom",orderedModifiers:[],options:Object.assign({},ot,o),modifiersData:{},elements:{reference:f,popper:s},attributes:{},styles:{}},l=[],m=!1,p={state:a,setOptions:function(y){var b=typeof y=="function"?y(a.options):y;h(),a.options=Object.assign({},o,a.options,b),a.scrollParents={reference:G(f)?se(f):f.contextElement?se(f.contextElement):[],popper:se(s)};var x=Br(kr([].concat(n,a.options.modifiers)));return a.orderedModifiers=x.filter(function(g){return g.enabled}),v(),p.update()},forceUpdate:function(){if(!m){var y=a.elements,b=y.reference,x=y.popper;if(at(b,x)){a.rects={reference:Sr(b,pe(x),a.options.strategy==="fixed"),popper:Le(x)},a.reset=!1,a.placement=a.options.placement,a.orderedModifiers.forEach(function(j){return a.modifiersData[j.name]=Object.assign({},j.data)});for(var g=0;g<a.orderedModifiers.length;g++){if(a.reset===!0){a.reset=!1,g=-1;continue}var w=a.orderedModifiers[g],O=w.fn,A=w.options,D=A===void 0?{}:A,E=w.name;typeof O=="function"&&(a=O({state:a,options:D,name:E,instance:p})||a)}}}},update:Tr(function(){return new Promise(function(d){p.forceUpdate(),d(a)})}),destroy:function(){h(),m=!0}};if(!at(f,s))return p;p.setOptions(u).then(function(d){!m&&u.onFirstUpdate&&u.onFirstUpdate(d)});function v(){a.orderedModifiers.forEach(function(d){var y=d.name,b=d.options,x=b===void 0?{}:b,g=d.effect;if(typeof g=="function"){var w=g({state:a,name:y,instance:p,options:x}),O=function(){};l.push(w||O)}})}function h(){l.forEach(function(d){return d()}),l=[]}return p}}const Hr=Wr({defaultModifiers:[wr,Er,or,sr,Ar,yr,Rr,tr]}),Ir=["enabled","placement","strategy","modifiers"];function Vr(e,t){if(e==null)return{};var r={},n=Object.keys(e),i,o;for(o=0;o<n.length;o++)i=n[o],!(t.indexOf(i)>=0)&&(r[i]=e[i]);return r}const Fr={name:"applyStyles",enabled:!1,phase:"afterWrite",fn:()=>{}},Ur={name:"ariaDescribedBy",enabled:!0,phase:"afterWrite",effect:({state:e})=>()=>{const{reference:t,popper:r}=e.elements;if("removeAttribute"in t){const n=(t.getAttribute("aria-describedby")||"").split(",").filter(i=>i.trim()!==r.id);n.length?t.setAttribute("aria-describedby",n.join(",")):t.removeAttribute("aria-describedby")}},fn:({state:e})=>{var t;const{popper:r,reference:n}=e.elements,i=(t=r.getAttribute("role"))==null?void 0:t.toLowerCase();if(r.id&&i==="tooltip"&&"setAttribute"in n){const o=n.getAttribute("aria-describedby");if(o&&o.split(",").indexOf(r.id)!==-1)return;n.setAttribute("aria-describedby",o?`${o},${r.id}`:r.id)}}},Kr=[];function rn(e,t,r={}){let{enabled:n=!0,placement:i="bottom",strategy:o="absolute",modifiers:c=Kr}=r,f=Vr(r,Ir);const s=P.useRef(c),u=P.useRef(),a=P.useCallback(()=>{var d;(d=u.current)==null||d.update()},[]),l=P.useCallback(()=>{var d;(d=u.current)==null||d.forceUpdate()},[]),[m,p]=kt(P.useState({placement:i,update:a,forceUpdate:l,attributes:{},styles:{popper:{},arrow:{}}})),v=P.useMemo(()=>({name:"updateStateModifier",enabled:!0,phase:"write",requires:["computeStyles"],fn:({state:d})=>{const y={},b={};Object.keys(d.elements).forEach(x=>{y[x]=d.styles[x],b[x]=d.attributes[x]}),p({state:d,styles:y,attributes:b,update:a,forceUpdate:l,placement:d.placement})}}),[a,l,p]),h=P.useMemo(()=>(oe(s.current,c)||(s.current=c),s.current),[c]);return P.useEffect(()=>{!u.current||!n||u.current.setOptions({placement:i,strategy:o,modifiers:[...h,v,Fr]})},[o,i,v,n,h]),P.useEffect(()=>{if(!(!n||e==null||t==null))return u.current=Hr(e,t,Object.assign({},f,{placement:i,strategy:o,modifiers:[...h,Ur,v]})),()=>{u.current!=null&&(u.current.destroy(),u.current=void 0,p(d=>Object.assign({},d,{attributes:{},styles:{popper:{}}})))}},[n,e,t]),m}var Nr=function(){},qr=Nr;const zr=Rt(qr),st=()=>{};function Xr(e){return e.button===0}function Yr(e){return!!(e.metaKey||e.altKey||e.ctrlKey||e.shiftKey)}const Pe=e=>e&&("current"in e?e.current:e),ft={click:"mousedown",mouseup:"mousedown",pointerup:"pointerdown"};function nn(e,t=st,{disabled:r,clickTrigger:n="click"}={}){const i=P.useRef(!1),o=P.useRef(!1),c=P.useCallback(u=>{const a=Pe(e);zr(!!a,"ClickOutside captured a close event but does not have a ref to compare it to. useClickOutside(), should be passed a ref that resolves to a DOM node"),i.current=!a||Yr(u)||!Xr(u)||!!Xe(a,u.target)||o.current,o.current=!1},[e]),f=De(u=>{const a=Pe(e);a&&Xe(a,u.target)&&(o.current=!0)}),s=De(u=>{i.current||t(u)});P.useEffect(()=>{var u,a;if(r||e==null)return;const l=Dt(Pe(e)),m=l.defaultView||window;let p=(u=m.event)!=null?u:(a=m.parent)==null?void 0:a.event,v=null;ft[n]&&(v=ge(l,ft[n],f,!0));const h=ge(l,n,c,!0),d=ge(l,n,b=>{if(b===p){p=void 0;return}s(b)});let y=[];return"ontouchstart"in l.documentElement&&(y=[].slice.call(l.body.children).map(b=>ge(b,"mousemove",st))),()=>{v==null||v(),h(),d(),y.forEach(b=>b())}},[e,r,n,c,f,s])}function _r(e){const t={};return Array.isArray(e)?(e==null||e.forEach(r=>{t[r.name]=r}),t):e||t}function Gr(e={}){return Array.isArray(e)?e:Object.keys(e).map(t=>(e[t].name=t,e[t]))}function on({enabled:e,enableEvents:t,placement:r,flip:n,offset:i,fixed:o,containerPadding:c,arrowElement:f,popperConfig:s={}}){var u,a,l,m,p;const v=_r(s.modifiers);return Object.assign({},s,{placement:r,enabled:e,strategy:o?"fixed":s.strategy,modifiers:Gr(Object.assign({},v,{eventListeners:{enabled:t,options:(u=v.eventListeners)==null?void 0:u.options},preventOverflow:Object.assign({},v.preventOverflow,{options:c?Object.assign({padding:c},(a=v.preventOverflow)==null?void 0:a.options):(l=v.preventOverflow)==null?void 0:l.options}),offset:{options:Object.assign({offset:i},(m=v.offset)==null?void 0:m.options)},arrow:Object.assign({},v.arrow,{enabled:!!f,options:Object.assign({},(p=v.arrow)==null?void 0:p.options,{element:f})}),flip:Object.assign({enabled:!!n},v.flip)}))})}export{tn as A,nn as a,en as b,Pe as g,on as m,rn as u};
