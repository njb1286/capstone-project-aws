import{r as c,u as O,j as o,c as j,R as le,a as M,m as x,f as ce,i as ue,S as de,g as fe,h as me}from"./index-1ba719d5.js";import{B as pe}from"./Button-8d81961f.js";import{A as ve,b as ye,a as he,g as ge,u as we,m as be}from"./mergeOptionsWithPopperConfig-a54c7578.js";import{b as k,o as Oe,l as _e,e as F,f as W,h as je}from"./useWindow-53bc5744.js";import{d as xe}from"./divWithClassName-1ffbf407.js";import{C as Ee,F as T,i as Ne,u as A,r as Re,h as B,a as L}from"./hasClass-e6c2a2c7.js";import"./index-9acdc5f6.js";const G=xe("h4");G.displayName="DivStyledAsH4";const K=c.forwardRef(({className:e,bsPrefix:t,as:n=G,...r},s)=>(t=O(t,"alert-heading"),o.jsx(n,{ref:s,className:j(e,t),...r})));K.displayName="AlertHeading";const Pe=K,V=c.forwardRef(({className:e,bsPrefix:t,as:n=ve,...r},s)=>(t=O(t,"alert-link"),o.jsx(n,{ref:s,className:j(e,t),...r})));V.displayName="AlertLink";const Ce=V,q=c.forwardRef((e,t)=>{const{bsPrefix:n,show:r=!0,closeLabel:s="Close alert",closeVariant:a,className:l,children:f,variant:i="primary",onClose:u,dismissible:v,transition:w=T,...y}=ye(e,{show:"onClose"}),h=O(n,"alert"),d=k(_=>{u&&u(!1,_)}),g=w===!0?T:w,m=o.jsxs("div",{role:"alert",...g?void 0:y,ref:t,className:j(l,h,i&&`${h}-${i}`,v&&`${h}-dismissible`),children:[v&&o.jsx(Ee,{onClick:d,"aria-label":s,variant:a}),f]});return g?o.jsx(g,{unmountOnExit:!0,...y,ref:void 0,in:r,children:m}):r?m:null});q.displayName="Alert";const I=Object.assign(q,{Link:Ce,Heading:Pe}),Se=()=>{};function Te(e,t,{disabled:n,clickTrigger:r}={}){const s=t||Se;he(e,s,{disabled:n,clickTrigger:r});const a=k(l=>{Ne(l)&&s(l)});c.useEffect(()=>{if(n||e==null)return;const l=Oe(ge(e));let f=(l.defaultView||window).event;const i=_e(l,"keyup",u=>{if(u===f){f=void 0;return}a(u)});return()=>{i()}},[e,n,a])}const J=c.forwardRef((e,t)=>{const{flip:n,offset:r,placement:s,containerPadding:a,popperConfig:l={},transition:f,runTransition:i}=e,[u,v]=F(),[w,y]=F(),h=W(v,t),d=A(e.container),g=A(e.target),[m,_]=c.useState(!e.show),p=we(g,u,be({placement:s,enableEvents:!!e.show,containerPadding:a||5,flip:n,offset:r,arrowElement:w,popperConfig:l}));e.show&&m&&_(!1);const E=(...ie)=>{_(!0),e.onExited&&e.onExited(...ie)},R=e.show||!m;if(Te(u,e.onHide,{disabled:!e.rootClose||e.rootCloseDisabled,clickTrigger:e.rootCloseEvent}),!R)return null;const{onExit:P,onExiting:N,onEnter:C,onEntering:S,onEntered:oe}=e;let H=e.children(Object.assign({},p.attributes.popper,{style:p.styles.popper,ref:h}),{popper:p,placement:s,show:!!e.show,arrowProps:Object.assign({},p.attributes.arrow,{style:p.styles.arrow,ref:y})});return H=Re(f,i,{in:!!e.show,appear:!0,mountOnEnter:!0,unmountOnExit:!0,children:H,onExit:P,onExiting:N,onExited:E,onEnter:C,onEntering:S,onEntered:oe}),d?le.createPortal(H,d):null});J.displayName="Overlay";const $e=J,Q=c.forwardRef(({className:e,bsPrefix:t,as:n="div",...r},s)=>(t=O(t,"popover-header"),o.jsx(n,{ref:s,className:j(e,t),...r})));Q.displayName="PopoverHeader";const De=Q,X=c.forwardRef(({className:e,bsPrefix:t,as:n="div",...r},s)=>(t=O(t,"popover-body"),o.jsx(n,{ref:s,className:j(e,t),...r})));X.displayName="PopoverBody";const Y=X;function Z(e,t){let n=e;return e==="left"?n=t?"end":"start":e==="right"&&(n=t?"start":"end"),n}function ee(e="absolute"){return{position:e,top:"0",left:"0",opacity:"0",pointerEvents:"none"}}const He=c.forwardRef(({bsPrefix:e,placement:t="right",className:n,style:r,children:s,body:a,arrowProps:l,hasDoneInitialMeasure:f,popper:i,show:u,...v},w)=>{const y=O(e,"popover"),h=M(),[d]=(t==null?void 0:t.split("-"))||[],g=Z(d,h);let m=r;return u&&!f&&(m={...r,...ee(i==null?void 0:i.strategy)}),o.jsxs("div",{ref:w,role:"tooltip",style:m,"x-placement":d,className:j(n,y,d&&`bs-popover-${g}`),...v,children:[o.jsx("div",{className:"popover-arrow",...l}),a?o.jsx(Y,{children:s}):s]})}),ke=Object.assign(He,{Header:De,Body:Y,POPPER_OFFSET:[0,8]}),te=c.forwardRef(({bsPrefix:e,placement:t="right",className:n,style:r,children:s,arrowProps:a,hasDoneInitialMeasure:l,popper:f,show:i,...u},v)=>{e=O(e,"tooltip");const w=M(),[y]=(t==null?void 0:t.split("-"))||[],h=Z(y,w);let d=r;return i&&!l&&(d={...r,...ee(f==null?void 0:f.strategy)}),o.jsxs("div",{ref:v,style:d,role:"tooltip","x-placement":y,className:j(n,e,`bs-tooltip-${h}`),...u,children:[o.jsx("div",{className:"tooltip-arrow",...a}),o.jsx("div",{className:`${e}-inner`,children:s})]})});te.displayName="Tooltip";const ne=Object.assign(te,{TOOLTIP_OFFSET:[0,6]});function Fe(e){const t=c.useRef(null),n=O(void 0,"popover"),r=O(void 0,"tooltip"),s=c.useMemo(()=>({name:"offset",options:{offset:()=>{if(e)return e;if(t.current){if(B(t.current,n))return ke.POPPER_OFFSET;if(B(t.current,r))return ne.TOOLTIP_OFFSET}return[0,0]}}}),[e,n,r]);return[t,[s]]}function Ae(e,t){const{ref:n}=e,{ref:r}=t;e.ref=n.__wrapped||(n.__wrapped=s=>n(L(s))),t.ref=r.__wrapped||(r.__wrapped=s=>r(L(s)))}const re=c.forwardRef(({children:e,transition:t=T,popperConfig:n={},rootClose:r=!1,placement:s="top",show:a=!1,...l},f)=>{const i=c.useRef({}),[u,v]=c.useState(null),[w,y]=Fe(l.offset),h=W(f,w),d=t===!0?T:t||void 0,g=k(m=>{v(m),n==null||n.onFirstUpdate==null||n.onFirstUpdate(m)});return je(()=>{u&&l.target&&(i.current.scheduleUpdate==null||i.current.scheduleUpdate())},[u,l.target]),c.useEffect(()=>{a||v(null)},[a]),o.jsx($e,{...l,ref:h,popperConfig:{...n,modifiers:y.concat(n.modifiers||[]),onFirstUpdate:g},transition:d,rootClose:r,placement:s,show:a,children:(m,{arrowProps:_,popper:p,show:E})=>{var R,P;Ae(m,_);const N=p==null?void 0:p.placement,C=Object.assign(i.current,{state:p==null?void 0:p.state,scheduleUpdate:p==null?void 0:p.update,placement:N,outOfBoundaries:(p==null||(R=p.state)==null||(P=R.modifiersData.hide)==null?void 0:P.isReferenceHidden)||!1,strategy:n.strategy}),S=!!u;return typeof e=="function"?e({...m,placement:N,show:E,...!t&&E&&{className:"show"},popper:C,arrowProps:_,hasDoneInitialMeasure:S}):c.cloneElement(e,{...m,placement:N,arrowProps:_,popper:C,hasDoneInitialMeasure:S,className:j(e.props.className,!t&&E&&"show"),style:{...e.props.style,...m.style}})}})});re.displayName="Overlay";const Be=re,Le="_container_cvrub_1",Ie="_title_cvrub_6",Ue="_button_cvrub_10",ze="_spinner_cvrub_15",Me="_visible_cvrub_18",We="_success_cvrub_22",Ge="_copy_cvrub_34",Ke="_tooltip_cvrub_68",b={container:Le,title:Ie,button:Ue,spinner:ze,visible:Me,success:We,"message-items":"_message-items_cvrub_28","copy-wrapper":"_copy-wrapper_cvrub_34",copy:Ge,"password-text":"_password-text_cvrub_56",tooltip:Ke};var se={color:void 0,size:void 0,className:void 0,style:void 0,attr:void 0},U=x.createContext&&x.createContext(se),Ve=["attr","size","title"];function qe(e,t){if(e==null)return{};var n=Je(e,t),r,s;if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(s=0;s<a.length;s++)r=a[s],!(t.indexOf(r)>=0)&&Object.prototype.propertyIsEnumerable.call(e,r)&&(n[r]=e[r])}return n}function Je(e,t){if(e==null)return{};var n={},r=Object.keys(e),s,a;for(a=0;a<r.length;a++)s=r[a],!(t.indexOf(s)>=0)&&(n[s]=e[s]);return n}function $(){return $=Object.assign?Object.assign.bind():function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e},$.apply(this,arguments)}function z(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter(function(s){return Object.getOwnPropertyDescriptor(e,s).enumerable})),n.push.apply(n,r)}return n}function D(e){for(var t=1;t<arguments.length;t++){var n=arguments[t]!=null?arguments[t]:{};t%2?z(Object(n),!0).forEach(function(r){Qe(e,r,n[r])}):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):z(Object(n)).forEach(function(r){Object.defineProperty(e,r,Object.getOwnPropertyDescriptor(n,r))})}return e}function Qe(e,t,n){return t=Xe(t),t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function Xe(e){var t=Ye(e,"string");return typeof t=="symbol"?t:String(t)}function Ye(e,t){if(typeof e!="object"||e===null)return e;var n=e[Symbol.toPrimitive];if(n!==void 0){var r=n.call(e,t||"default");if(typeof r!="object")return r;throw new TypeError("@@toPrimitive must return a primitive value.")}return(t==="string"?String:Number)(e)}function ae(e){return e&&e.map((t,n)=>x.createElement(t.tag,D({key:n},t.attr),ae(t.child)))}function Ze(e){return t=>x.createElement(et,$({attr:D({},e.attr)},t),ae(e.child))}function et(e){var t=n=>{var{attr:r,size:s,title:a}=e,l=qe(e,Ve),f=s||n.size||"1em",i;return n.className&&(i=n.className),e.className&&(i=(i?i+" ":"")+e.className),x.createElement("svg",$({stroke:"currentColor",fill:"currentColor",strokeWidth:"0"},n.attr,r,l,{className:i,style:D(D({color:e.color||n.color},n.style),e.style),height:f,width:f,xmlns:"http://www.w3.org/2000/svg"}),a&&x.createElement("title",null,a),e.children)};return U!==void 0?x.createElement(U.Consumer,null,n=>t(n)):t(se)}function tt(e){return Ze({tag:"svg",attr:{viewBox:"0 0 448 512"},child:[{tag:"path",attr:{d:"M320 448v40c0 13.255-10.745 24-24 24H24c-13.255 0-24-10.745-24-24V120c0-13.255 10.745-24 24-24h72v296c0 30.879 25.121 56 56 56h168zm0-344V0H152c-13.255 0-24 10.745-24 24v368c0 13.255 10.745 24 24 24h272c13.255 0 24-10.745 24-24V128H344c-13.2 0-24-10.8-24-24zm120.971-31.029L375.029 7.029A24 24 0 0 0 358.059 0H352v96h96v-6.059a24 24 0 0 0-7.029-16.97z"},child:[]}]})(e)}const ct=()=>{const e=ce(),t=ue(d=>d.tempPassword),[n,r]=c.useState(!1),[s,a]=c.useState(null),[l,f]=c.useState(!1),i=c.useRef(null),u=c.useRef(null),v=async()=>{const d=await fetch(`${fe}/generate-password`,me("GET"));if(d.status!==200){a("Something went wrong");return}const g=await d.json();if("message"in g){a(g.message);return}e({type:"SET_TEMP_PASSWORD",payload:g.password})},w=async()=>{a(null),r(!0),await v(),r(!1)},y=()=>{t&&(navigator.clipboard.writeText(t),f(!0),setTimeout(()=>{f(!1)},2e3))},h=()=>{u.current&&u.current.select()};return o.jsxs("div",{className:`d-flex fs-4 justify-content-start align-items-center flex-column vh-100 ${b.container}`,children:[o.jsx("h1",{className:b.title,children:"Generate a single use password"}),o.jsx(de,{className:`${b.spinner} ${n?b.visible:""}`,variant:"primary",animation:"border"}),o.jsx(pe,{disabled:n,onClick:w,variant:"primary",size:"lg",className:b.button,children:"Generate"}),s&&o.jsx(I,{variant:"danger",children:s}),t&&o.jsx(I,{variant:"success",className:b.success,children:o.jsxs("div",{className:b["message-items"],children:[o.jsx("textarea",{value:t,onClick:h,ref:u,rows:1,readOnly:!0,className:b["password-text"]}),o.jsx(Be,{target:i.current,show:l,placement:"top",children:d=>o.jsx(ne,{className:b.tooltip,id:"copy-tooltip",...d,children:"Copied!"})}),o.jsx("button",{onClick:y,ref:i,className:b["copy-wrapper"],children:o.jsx("div",{className:b.copy,children:o.jsx(tt,{})})})]})})]})};export{ct as default};
