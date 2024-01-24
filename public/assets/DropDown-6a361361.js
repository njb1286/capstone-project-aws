import{r as a,j as g,m as R,u as T,c as A,a as ke}from"./index-317d8359.js";import{d as ee,u as Se,q as Z}from"./DataKey-b347a936.js";import{b as W,e as je,u as Ne,g as Pe,f as te,h as Me}from"./useWindow-bf0ff39f.js";import{u as Ee,m as Ie,a as Re,A as Te,b as Ae}from"./mergeOptionsWithPopperConfig-a19472ac.js";import{a as We,B as Ke}from"./Button-d61ddca3.js";function Fe(t,e,n,r=!1){const o=W(n);a.useEffect(()=>{const s=typeof t=="function"?t():t;return s.addEventListener(e,o,r),()=>s.removeEventListener(e,o,r)},[t])}function Ge(t,e,n){const r=a.useRef(t!==void 0),[o,s]=a.useState(e),c=t!==void 0,i=r.current;return r.current=c,!c&&i&&o!==e&&s(e),[c?t:o,a.useCallback((...d)=>{const[l,...f]=d;let u=n==null?void 0:n(l,...f);return s(l),u},[n])]}function He(){const[,t]=a.useReducer(e=>!e,!1);return t}const Oe=a.createContext(null),z=Oe,qe=["children"];function ze(t,e){if(t==null)return{};var n={},r=Object.keys(t),o,s;for(s=0;s<r.length;s++)o=r[s],!(e.indexOf(o)>=0)&&(n[o]=t[o]);return n}const Ue=()=>{};function ne(t={}){const e=a.useContext(z),[n,r]=je(),o=a.useRef(!1),{flip:s,offset:c,rootCloseEvent:i,fixed:d=!1,placement:l,popperConfig:f={},enableEventListeners:u=!0,usePopper:h=!!e}=t,w=(e==null?void 0:e.show)==null?!!t.show:e.show;w&&!o.current&&(o.current=!0);const D=E=>{e==null||e.toggle(!1,E)},{placement:k,setMenu:b,menuElement:P,toggleElement:S}=e||{},x=Ee(S,P,Ie({placement:l||k||"bottom-start",enabled:h,enableEvents:u??w,offset:c,flip:s,fixed:d,arrowElement:n,popperConfig:f})),M=Object.assign({ref:b||Ue,"aria-labelledby":S==null?void 0:S.id},x.attributes.popper,{style:x.styles.popper}),$={show:w,placement:k,hasShown:o.current,toggle:e==null?void 0:e.toggle,popper:h?x:null,arrowProps:h?Object.assign({ref:r},x.attributes.arrow,{style:x.styles.arrow}):{}};return Re(P,D,{clickTrigger:i,disabled:!w}),[M,$]}const Be={usePopper:!0};function Q(t){let{children:e}=t,n=ze(t,qe);const[r,o]=ne(n);return g.jsx(g.Fragment,{children:e(r,o)})}Q.displayName="DropdownMenu";Q.defaultProps=Be;const q={prefix:String(Math.round(Math.random()*1e10)),current:0},oe=R.createContext(q),Je=R.createContext(!1);let Qe=!!(typeof window<"u"&&window.document&&window.document.createElement),B=new WeakMap;function Ve(t=!1){let e=a.useContext(oe),n=a.useRef(null);if(n.current===null&&!t){var r,o;let s=(o=R.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED)===null||o===void 0||(r=o.ReactCurrentOwner)===null||r===void 0?void 0:r.current;if(s){let c=B.get(s);c==null?B.set(s,{id:e.current,state:s.memoizedState}):s.memoizedState!==c.state&&(e.current=c.id,B.delete(s))}n.current=++e.current}return n.current}function Xe(t){let e=a.useContext(oe);e===q&&!Qe&&console.warn("When server rendering, you must wrap your application in an <SSRProvider> to ensure consistent ids are generated between the client and server.");let n=Ve(!!t),r=`react-aria${e.prefix}`;return t||`${r}-${n}`}function Ze(t){let e=R.useId(),[n]=a.useState(tt()),r=n?"react-aria":`react-aria${q.prefix}`;return t||`${r}-${e}`}const Le=typeof R.useId=="function"?Ze:Xe;function Ye(){return!1}function _e(){return!0}function et(t){return()=>{}}function tt(){return typeof R.useSyncExternalStore=="function"?R.useSyncExternalStore(et,Ye,_e):a.useContext(Je)}const re=t=>{var e;return((e=t.getAttribute("role"))==null?void 0:e.toLowerCase())==="menu"},L=()=>{};function se(){const t=Le(),{show:e=!1,toggle:n=L,setToggle:r,menuElement:o}=a.useContext(z)||{},s=a.useCallback(i=>{n(!e,i)},[e,n]),c={id:t,ref:r||L,onClick:s,"aria-expanded":!!e};return o&&re(o)&&(c["aria-haspopup"]=!0),[c,{show:e,toggle:n}]}function ae({children:t}){const[e,n]=se();return g.jsx(g.Fragment,{children:t(e,n)})}ae.displayName="DropdownToggle";const nt=a.createContext(null),Y=(t,e=null)=>t!=null?String(t):e||null,J=nt,ce=a.createContext(null);ce.displayName="NavContext";const ot=ce,rt=["eventKey","disabled","onClick","active","as"];function st(t,e){if(t==null)return{};var n={},r=Object.keys(t),o,s;for(s=0;s<r.length;s++)o=r[s],!(e.indexOf(o)>=0)&&(n[o]=t[o]);return n}function ue({key:t,href:e,active:n,disabled:r,onClick:o}){const s=a.useContext(J),c=a.useContext(ot),{activeKey:i}=c||{},d=Y(t,e),l=n==null&&t!=null?Y(i)===d:n;return[{onClick:W(u=>{r||(o==null||o(u),s&&!u.isPropagationStopped()&&s(d,u))}),"aria-disabled":r||void 0,"aria-selected":l,[ee("dropdown-item")]:""},{isActive:l}]}const le=a.forwardRef((t,e)=>{let{eventKey:n,disabled:r,onClick:o,active:s,as:c=We}=t,i=st(t,rt);const[d]=ue({key:n,href:i.href,disabled:r,onClick:o,active:s});return g.jsx(c,Object.assign({},i,{ref:e},d))});le.displayName="DropdownItem";function _(){const t=He(),e=a.useRef(null),n=a.useCallback(r=>{e.current=r,t()},[t]);return[e,n]}function H({defaultShow:t,show:e,onSelect:n,onToggle:r,itemSelector:o=`* [${ee("dropdown-item")}]`,focusFirstItemOnShow:s,placement:c="bottom-start",children:i}){const d=Ne(),[l,f]=Ge(e,t,r),[u,h]=_(),w=u.current,[D,k]=_(),b=D.current,P=Se(l),S=a.useRef(null),x=a.useRef(!1),M=a.useContext(J),$=a.useCallback((p,m,v=m==null?void 0:m.type)=>{f(p,{originalEvent:m,source:v})},[f]),E=W((p,m)=>{n==null||n(p,m),$(!1,m,"select"),m.isPropagationStopped()||M==null||M(p,m)}),y=a.useMemo(()=>({toggle:$,placement:c,show:l,menuElement:w,toggleElement:b,setMenu:h,setToggle:k}),[$,c,l,w,b,h,k]);w&&P&&!l&&(x.current=w.contains(w.ownerDocument.activeElement));const C=W(()=>{b&&b.focus&&b.focus()}),K=W(()=>{const p=S.current;let m=s;if(m==null&&(m=u.current&&re(u.current)?"keyboard":!1),m===!1||m==="keyboard"&&!/^key.+$/.test(p))return;const v=Z(u.current,o)[0];v&&v.focus&&v.focus()});a.useEffect(()=>{l?K():x.current&&(x.current=!1,C())},[l,x,C,K]),a.useEffect(()=>{S.current=null});const F=(p,m)=>{if(!u.current)return null;const v=Z(u.current,o);let N=v.indexOf(p)+m;return N=Math.max(0,Math.min(N,v.length)),v[N]};return Fe(a.useCallback(()=>d.document,[d]),"keydown",p=>{var m,v;const{key:N}=p,I=p.target,V=(m=u.current)==null?void 0:m.contains(I),De=(v=D.current)==null?void 0:v.contains(I);if(/input|textarea/i.test(I.tagName)&&(N===" "||N!=="Escape"&&V||N==="Escape"&&I.type==="search")||!V&&!De||N==="Tab"&&(!u.current||!l))return;S.current=p.type;const U={originalEvent:p,source:p.type};switch(N){case"ArrowUp":{const j=F(I,-1);j&&j.focus&&j.focus(),p.preventDefault();return}case"ArrowDown":if(p.preventDefault(),!l)f(!0,U);else{const j=F(I,1);j&&j.focus&&j.focus()}return;case"Tab":Pe(I.ownerDocument,"keyup",j=>{var X;(j.key==="Tab"&&!j.target||!((X=u.current)!=null&&X.contains(j.target)))&&f(!1,U)},{once:!0});break;case"Escape":N==="Escape"&&(p.preventDefault(),p.stopPropagation()),f(!1,U);break}}),g.jsx(J.Provider,{value:E,children:g.jsx(z.Provider,{value:y,children:i})})}H.displayName="Dropdown";H.Menu=Q;H.Toggle=ae;H.Item=le;const ie=a.createContext({});ie.displayName="DropdownContext";const de=ie,fe=a.forwardRef(({className:t,bsPrefix:e,as:n="hr",role:r="separator",...o},s)=>(e=T(e,"dropdown-divider"),g.jsx(n,{ref:s,className:A(t,e),role:r,...o})));fe.displayName="DropdownDivider";const at=fe,pe=a.forwardRef(({className:t,bsPrefix:e,as:n="div",role:r="heading",...o},s)=>(e=T(e,"dropdown-header"),g.jsx(n,{ref:s,className:A(t,e),role:r,...o})));pe.displayName="DropdownHeader";const ct=pe,me=a.forwardRef(({bsPrefix:t,className:e,eventKey:n,disabled:r=!1,onClick:o,active:s,as:c=Te,...i},d)=>{const l=T(t,"dropdown-item"),[f,u]=ue({key:n,href:i.href,disabled:r,onClick:o,active:s});return g.jsx(c,{...i,...f,ref:d,className:A(e,l,u.isActive&&"active",r&&"disabled")})});me.displayName="DropdownItem";const ut=me,ge=a.forwardRef(({className:t,bsPrefix:e,as:n="span",...r},o)=>(e=T(e,"dropdown-item-text"),g.jsx(n,{ref:o,className:A(t,e),...r})));ge.displayName="DropdownItemText";const lt=ge,we=a.createContext(null);we.displayName="InputGroupContext";const xe=we,he=a.createContext(null);he.displayName="NavbarContext";const it=he;function $e(t,e){return t}function ve(t,e,n){const r=n?"top-end":"top-start",o=n?"top-start":"top-end",s=n?"bottom-end":"bottom-start",c=n?"bottom-start":"bottom-end",i=n?"right-start":"left-start",d=n?"right-end":"left-end",l=n?"left-start":"right-start",f=n?"left-end":"right-end";let u=t?c:s;return e==="up"?u=t?o:r:e==="end"?u=t?f:l:e==="start"?u=t?d:i:e==="down-centered"?u="bottom":e==="up-centered"&&(u="top"),u}const Ce=a.forwardRef(({bsPrefix:t,className:e,align:n,rootCloseEvent:r,flip:o=!0,show:s,renderOnMount:c,as:i="div",popperConfig:d,variant:l,...f},u)=>{let h=!1;const w=a.useContext(it),D=T(t,"dropdown-menu"),{align:k,drop:b,isRTL:P}=a.useContext(de);n=n||k;const S=a.useContext(xe),x=[];if(n)if(typeof n=="object"){const p=Object.keys(n);if(p.length){const m=p[0],v=n[m];h=v==="start",x.push(`${D}-${m}-${v}`)}}else n==="end"&&(h=!0);const M=ve(h,b,P),[$,{hasShown:E,popper:y,show:C,toggle:K}]=ne({flip:o,rootCloseEvent:r,show:s,usePopper:!w&&x.length===0,offset:[0,2],popperConfig:d,placement:M});if($.ref=te($e(u),$.ref),Me(()=>{C&&(y==null||y.update())},[C]),!E&&!c&&!S)return null;typeof i!="string"&&($.show=C,$.close=()=>K==null?void 0:K(!1),$.align=n);let F=f.style;return y!=null&&y.placement&&(F={...f.style,...$.style},f["x-placement"]=y.placement),g.jsx(i,{...f,...$,style:F,...(x.length||w)&&{"data-bs-popper":"static"},className:A(e,D,C&&"show",h&&`${D}-end`,l&&`${D}-${l}`,...x)})});Ce.displayName="DropdownMenu";const dt=Ce,be=a.forwardRef(({bsPrefix:t,split:e,className:n,childBsPrefix:r,as:o=Ke,...s},c)=>{const i=T(t,"dropdown-toggle"),d=a.useContext(z);r!==void 0&&(s.bsPrefix=r);const[l]=se();return l.ref=te(l.ref,$e(c)),g.jsx(o,{className:A(n,i,e&&`${i}-split`,(d==null?void 0:d.show)&&"show"),...l,...s})});be.displayName="DropdownToggle";const ft=be,ye=a.forwardRef((t,e)=>{const{bsPrefix:n,drop:r="down",show:o,className:s,align:c="start",onSelect:i,onToggle:d,focusFirstItemOnShow:l,as:f="div",navbar:u,autoClose:h=!0,...w}=Ae(t,{show:"onToggle"}),D=a.useContext(xe),k=T(n,"dropdown"),b=ke(),P=y=>h===!1?y==="click":h==="inside"?y!=="rootClose":h==="outside"?y!=="select":!0,S=W((y,C)=>{C.originalEvent.currentTarget===document&&(C.source!=="keydown"||C.originalEvent.key==="Escape")&&(C.source="rootClose"),P(C.source)&&(d==null||d(y,C))}),M=ve(c==="end",r,b),$=a.useMemo(()=>({align:c,drop:r,isRTL:b}),[c,r,b]),E={down:k,"down-centered":`${k}-center`,up:"dropup","up-centered":"dropup-center dropup",end:"dropend",start:"dropstart"};return g.jsx(de.Provider,{value:$,children:g.jsx(H,{placement:M,show:o,onSelect:i,onToggle:S,focusFirstItemOnShow:l,itemSelector:`.${k}-item:not(.disabled):not(:disabled)`,children:D?w.children:g.jsx(f,{...w,ref:e,className:A(s,o&&"show",E[r])})})})});ye.displayName="Dropdown";const O=Object.assign(ye,{Toggle:ft,Menu:dt,Item:ut,ItemText:lt,Divider:at,Header:ct}),pt="_categories_keasm_1",mt="_active_keasm_9",gt="_menu_keasm_15",G={categories:pt,"category-item":"_category-item_keasm_6",active:mt,menu:gt};function bt(t){const[e,n]=a.useState(t.default),r=o=>{var c;o.preventDefault();const s=o.target;n(s.textContent),(c=t.onSelect)==null||c.call(t,s.textContent)};return g.jsxs(O,{className:`${G.dropdown} ${t.className??""}`,children:[g.jsxs(O.Toggle,{className:G.categories,children:[t.title&&`${t.title}: `,e]}),g.jsx(O.Menu,{className:`dropdown-menu ${G.menu}`,children:t.categories.map(o=>g.jsx(O.Item,{className:`${G["category-item"]} ${e.toLowerCase()===o.toLowerCase()?G.active:""}`,as:"button",onClick:r,children:o},`category_${o}`))})]})}export{bt as D,xe as I};
