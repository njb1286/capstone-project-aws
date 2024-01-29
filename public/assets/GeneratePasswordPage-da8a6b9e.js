import{r,u as x,j as o,c as E,R as te,a as B,f as se,i as ne,S as ae,g as oe,h as re}from"./index-a92a2e79.js";import{B as ie}from"./Button-58481d39.js";import{F as le}from"./index-02c45f2e.js";import{A as ce,b as de,a as ue,g as fe,u as pe,m as me}from"./mergeOptionsWithPopperConfig-b756c39e.js";import{b as F,o as ve,l as he,e as k,f as L,h as ye}from"./useWindow-ee83e482.js";import{d as ge}from"./divWithClassName-a2df187c.js";import{C as we,F as S,i as _e,u as A,r as xe,h as H,a as D}from"./hasClass-2fb303be.js";import"./index-28b5e842.js";const U=ge("h4");U.displayName="DivStyledAsH4";const M=r.forwardRef(({className:e,bsPrefix:t,as:s=U,...n},a)=>(t=x(t,"alert-heading"),o.jsx(s,{ref:a,className:E(e,t),...n})));M.displayName="AlertHeading";const Re=M,I=r.forwardRef(({className:e,bsPrefix:t,as:s=ce,...n},a)=>(t=x(t,"alert-link"),o.jsx(s,{ref:a,className:E(e,t),...n})));I.displayName="AlertLink";const Ee=I,G=r.forwardRef((e,t)=>{const{bsPrefix:s,show:n=!0,closeLabel:a="Close alert",closeVariant:d,className:i,children:f,variant:u="primary",onClose:l,dismissible:v,transition:w=S,...h}=de(e,{show:"onClose"}),y=x(s,"alert"),c=F(R=>{l&&l(!1,R)}),g=w===!0?S:w,p=o.jsxs("div",{role:"alert",...g?void 0:h,ref:t,className:E(i,y,u&&`${y}-${u}`,v&&`${y}-dismissible`),children:[v&&o.jsx(we,{onClick:c,"aria-label":a,variant:d}),f]});return g?o.jsx(g,{unmountOnExit:!0,...h,ref:void 0,in:n,children:p}):n?p:null});G.displayName="Alert";const P=Object.assign(G,{Link:Ee,Heading:Re}),Ne=()=>{};function be(e,t,{disabled:s,clickTrigger:n}={}){const a=t||Ne;ue(e,a,{disabled:s,clickTrigger:n});const d=F(i=>{_e(i)&&a(i)});r.useEffect(()=>{if(s||e==null)return;const i=ve(fe(e));let f=(i.defaultView||window).event;const u=he(i,"keyup",l=>{if(l===f){f=void 0;return}d(l)});return()=>{u()}},[e,s,d])}const W=r.forwardRef((e,t)=>{const{flip:s,offset:n,placement:a,containerPadding:d,popperConfig:i={},transition:f,runTransition:u}=e,[l,v]=k(),[w,h]=k(),y=L(v,t),c=A(e.container),g=A(e.target),[p,R]=r.useState(!e.show),m=pe(g,l,me({placement:a,enableEvents:!!e.show,containerPadding:d||5,flip:s,offset:n,arrowElement:w,popperConfig:i}));e.show&&p&&R(!1);const N=(...ee)=>{R(!0),e.onExited&&e.onExited(...ee)},j=e.show||!p;if(be(l,e.onHide,{disabled:!e.rootClose||e.rootCloseDisabled,clickTrigger:e.rootCloseEvent}),!j)return null;const{onExit:O,onExiting:b,onEnter:T,onEntering:C,onEntered:Z}=e;let $=e.children(Object.assign({},m.attributes.popper,{style:m.styles.popper,ref:y}),{popper:m,placement:a,show:!!e.show,arrowProps:Object.assign({},m.attributes.arrow,{style:m.styles.arrow,ref:h})});return $=xe(f,u,{in:!!e.show,appear:!0,mountOnEnter:!0,unmountOnExit:!0,children:$,onExit:O,onExiting:b,onExited:N,onEnter:T,onEntering:C,onEntered:Z}),c?te.createPortal($,c):null});W.displayName="Overlay";const je=W,K=r.forwardRef(({className:e,bsPrefix:t,as:s="div",...n},a)=>(t=x(t,"popover-header"),o.jsx(s,{ref:a,className:E(e,t),...n})));K.displayName="PopoverHeader";const Oe=K,V=r.forwardRef(({className:e,bsPrefix:t,as:s="div",...n},a)=>(t=x(t,"popover-body"),o.jsx(s,{ref:a,className:E(e,t),...n})));V.displayName="PopoverBody";const q=V;function z(e,t){let s=e;return e==="left"?s=t?"end":"start":e==="right"&&(s=t?"start":"end"),s}function J(e="absolute"){return{position:e,top:"0",left:"0",opacity:"0",pointerEvents:"none"}}const Te=r.forwardRef(({bsPrefix:e,placement:t="right",className:s,style:n,children:a,body:d,arrowProps:i,hasDoneInitialMeasure:f,popper:u,show:l,...v},w)=>{const h=x(e,"popover"),y=B(),[c]=(t==null?void 0:t.split("-"))||[],g=z(c,y);let p=n;return l&&!f&&(p={...n,...J(u==null?void 0:u.strategy)}),o.jsxs("div",{ref:w,role:"tooltip",style:p,"x-placement":c,className:E(s,h,c&&`bs-popover-${g}`),...v,children:[o.jsx("div",{className:"popover-arrow",...i}),d?o.jsx(q,{children:a}):a]})}),Ce=Object.assign(Te,{Header:Oe,Body:q,POPPER_OFFSET:[0,8]}),Q=r.forwardRef(({bsPrefix:e,placement:t="right",className:s,style:n,children:a,arrowProps:d,hasDoneInitialMeasure:i,popper:f,show:u,...l},v)=>{e=x(e,"tooltip");const w=B(),[h]=(t==null?void 0:t.split("-"))||[],y=z(h,w);let c=n;return u&&!i&&(c={...n,...J(f==null?void 0:f.strategy)}),o.jsxs("div",{ref:v,style:c,role:"tooltip","x-placement":h,className:E(s,e,`bs-tooltip-${y}`),...l,children:[o.jsx("div",{className:"tooltip-arrow",...d}),o.jsx("div",{className:`${e}-inner`,children:a})]})});Q.displayName="Tooltip";const X=Object.assign(Q,{TOOLTIP_OFFSET:[0,6]});function Se(e){const t=r.useRef(null),s=x(void 0,"popover"),n=x(void 0,"tooltip"),a=r.useMemo(()=>({name:"offset",options:{offset:()=>{if(e)return e;if(t.current){if(H(t.current,s))return Ce.POPPER_OFFSET;if(H(t.current,n))return X.TOOLTIP_OFFSET}return[0,0]}}}),[e,s,n]);return[t,[a]]}function $e(e,t){const{ref:s}=e,{ref:n}=t;e.ref=s.__wrapped||(s.__wrapped=a=>s(D(a))),t.ref=n.__wrapped||(n.__wrapped=a=>n(D(a)))}const Y=r.forwardRef(({children:e,transition:t=S,popperConfig:s={},rootClose:n=!1,placement:a="top",show:d=!1,...i},f)=>{const u=r.useRef({}),[l,v]=r.useState(null),[w,h]=Se(i.offset),y=L(f,w),c=t===!0?S:t||void 0,g=F(p=>{v(p),s==null||s.onFirstUpdate==null||s.onFirstUpdate(p)});return ye(()=>{l&&i.target&&(u.current.scheduleUpdate==null||u.current.scheduleUpdate())},[l,i.target]),r.useEffect(()=>{d||v(null)},[d]),o.jsx(je,{...i,ref:y,popperConfig:{...s,modifiers:h.concat(s.modifiers||[]),onFirstUpdate:g},transition:c,rootClose:n,placement:a,show:d,children:(p,{arrowProps:R,popper:m,show:N})=>{var j,O;$e(p,R);const b=m==null?void 0:m.placement,T=Object.assign(u.current,{state:m==null?void 0:m.state,scheduleUpdate:m==null?void 0:m.update,placement:b,outOfBoundaries:(m==null||(j=m.state)==null||(O=j.modifiersData.hide)==null?void 0:O.isReferenceHidden)||!1,strategy:s.strategy}),C=!!l;return typeof e=="function"?e({...p,placement:b,show:N,...!t&&N&&{className:"show"},popper:T,arrowProps:R,hasDoneInitialMeasure:C}):r.cloneElement(e,{...p,placement:b,arrowProps:R,popper:T,hasDoneInitialMeasure:C,className:E(e.props.className,!t&&N&&"show"),style:{...e.props.style,...p.style}})}})});Y.displayName="Overlay";const Fe=Y,ke="_container_cvrub_1",Ae="_title_cvrub_6",He="_button_cvrub_10",De="_spinner_cvrub_15",Pe="_visible_cvrub_18",Be="_success_cvrub_22",Le="_copy_cvrub_34",Ue="_tooltip_cvrub_68",_={container:ke,title:Ae,button:He,spinner:De,visible:Pe,success:Be,"message-items":"_message-items_cvrub_28","copy-wrapper":"_copy-wrapper_cvrub_34",copy:Le,"password-text":"_password-text_cvrub_56",tooltip:Ue},Je=()=>{const e=se(),t=ne(c=>c.tempPassword),[s,n]=r.useState(!1),[a,d]=r.useState(null),[i,f]=r.useState(!1),u=r.useRef(null),l=r.useRef(null),v=async()=>{const c=await fetch(`${oe}/generate-password`,re("GET"));if(c.status!==200){d("Something went wrong");return}const g=await c.json();if("message"in g){d(g.message);return}e({type:"SET_TEMP_PASSWORD",payload:g.password})},w=async()=>{d(null),n(!0),await v(),n(!1)},h=()=>{t&&(navigator.clipboard.writeText(t),f(!0),setTimeout(()=>{f(!1)},2e3))},y=()=>{l.current&&l.current.select()};return o.jsxs("div",{className:`d-flex fs-4 justify-content-start align-items-center flex-column vh-100 ${_.container}`,children:[o.jsx("h1",{className:_.title,children:"Generate a single use password"}),o.jsx(ae,{className:`${_.spinner} ${s?_.visible:""}`,variant:"primary",animation:"border"}),o.jsx(ie,{disabled:s,onClick:w,variant:"primary",size:"lg",className:_.button,children:"Generate"}),a&&o.jsx(P,{variant:"danger",children:a}),t&&o.jsx(P,{variant:"success",className:_.success,children:o.jsxs("div",{className:_["message-items"],children:[o.jsx("textarea",{value:t,onClick:y,ref:l,rows:1,readOnly:!0,className:_["password-text"]}),o.jsx(Fe,{target:u.current,show:i,placement:"top",children:c=>o.jsx(X,{className:_.tooltip,id:"copy-tooltip",...c,children:"Copied!"})}),o.jsx("button",{onClick:h,ref:u,className:_["copy-wrapper"],children:o.jsx("div",{className:_.copy,children:o.jsx(le,{})})})]})})]})};export{Je as default};
