import{r as i,j as o,R as Ye,u as L,c as C,a as Pe,b as Je,d as Qe,e as Ze,f as et,g as tt,h as nt}from"./index-ce9b76f3.js";import{c as ye,o as _e,u as Be,a as ot,b as x,l as we,d as Me,e as st,f as at,r as Ne,g as rt}from"./useWindow-562e5128.js";import{s as X,u as it,i as lt,r as xe,h as dt,C as ct,F as De,t as ut}from"./hasClass-46380227.js";import{d as mt,u as ft,q as A}from"./DataKey-d83cf9f3.js";import{d as ht}from"./divWithClassName-8ca83073.js";import{u as gt}from"./useGetImageItem-373674a7.js";import{u as pt}from"./useLazyImage-2f799df2.js";import{C as Ce}from"./CardBody-bfaef572.js";import{B as yt}from"./ButtonGroup-9ec0e847.js";import{B as Re}from"./Button-af0a51b0.js";import"./index-0a2d08ea.js";function vt(t){const e=i.useRef(t);return e.current=t,e}function Oe(t){const e=vt(t);i.useEffect(()=>()=>e.current(),[])}var ae;function Te(t){if((!ae&&ae!==0||t)&&ye){var e=document.createElement("div");e.style.position="absolute",e.style.top="-9999px",e.style.width="50px",e.style.height="50px",e.style.overflow="scroll",document.body.appendChild(e),ae=e.offsetWidth-e.clientWidth,document.body.removeChild(e)}return ae}function fe(t){t===void 0&&(t=_e());try{var e=t.activeElement;return!e||!e.nodeName?null:e}catch{return t.body}}function Et(t=document){const e=t.defaultView;return Math.abs(e.innerWidth-t.documentElement.clientWidth)}const je=mt("modal-open");class bt{constructor({ownerDocument:e,handleContainerOverflow:n=!0,isRTL:s=!1}={}){this.handleContainerOverflow=n,this.isRTL=s,this.modals=[],this.ownerDocument=e}getScrollbarWidth(){return Et(this.ownerDocument)}getElement(){return(this.ownerDocument||document).body}setModalAttributes(e){}removeModalAttributes(e){}setContainerStyle(e){const n={overflow:"hidden"},s=this.isRTL?"paddingLeft":"paddingRight",a=this.getElement();e.style={overflow:a.style.overflow,[s]:a.style[s]},e.scrollBarWidth&&(n[s]=`${parseInt(X(a,s)||"0",10)+e.scrollBarWidth}px`),a.setAttribute(je,""),X(a,n)}reset(){[...this.modals].forEach(e=>this.remove(e))}removeContainerStyle(e){const n=this.getElement();n.removeAttribute(je),Object.assign(n.style,e.style)}add(e){let n=this.modals.indexOf(e);return n!==-1||(n=this.modals.length,this.modals.push(e),this.setModalAttributes(e),n!==0)||(this.state={scrollBarWidth:this.getScrollbarWidth(),style:{}},this.handleContainerOverflow&&this.setContainerStyle(this.state)),n}remove(e){const n=this.modals.indexOf(e);n!==-1&&(this.modals.splice(n,1),!this.modals.length&&this.handleContainerOverflow&&this.removeContainerStyle(this.state),this.removeModalAttributes(e))}isTopModal(e){return!!this.modals.length&&this.modals[this.modals.length-1]===e}}const ve=bt,wt=["show","role","className","style","children","backdrop","keyboard","onBackdropClick","onEscapeKeyDown","transition","runTransition","backdropTransition","runBackdropTransition","autoFocus","enforceFocus","restoreFocus","restoreFocusOptions","renderDialog","renderBackdrop","manager","container","onShow","onHide","onExit","onExited","onExiting","onEnter","onEntering","onEntered"];function Mt(t,e){if(t==null)return{};var n={},s=Object.keys(t),a,r;for(r=0;r<s.length;r++)a=s[r],!(e.indexOf(a)>=0)&&(n[a]=t[a]);return n}let he;function Nt(t){return he||(he=new ve({ownerDocument:t==null?void 0:t.document})),he}function xt(t){const e=Be(),n=t||Nt(e),s=i.useRef({dialog:null,backdrop:null});return Object.assign(s.current,{add:()=>n.add(s.current),remove:()=>n.remove(s.current),isTopModal:()=>n.isTopModal(s.current),setDialogRef:i.useCallback(a=>{s.current.dialog=a},[]),setBackdropRef:i.useCallback(a=>{s.current.backdrop=a},[])})}const Se=i.forwardRef((t,e)=>{let{show:n=!1,role:s="dialog",className:a,style:r,children:m,backdrop:u=!0,keyboard:y=!0,onBackdropClick:E,onEscapeKeyDown:h,transition:f,runTransition:b,backdropTransition:R,runBackdropTransition:k,autoFocus:I=!0,enforceFocus:w=!0,restoreFocus:F=!0,restoreFocusOptions:v,renderDialog:_,renderBackdrop:re=d=>o.jsx("div",Object.assign({},d)),manager:ie,container:le,onShow:W,onHide:Y=()=>{},onExit:P,onExited:H,onExiting:J,onEnter:Q,onEntering:Z,onEntered:de}=t,ce=Mt(t,wt);const M=Be(),B=it(le),c=xt(ie),ee=ot(),U=ft(n),[T,N]=i.useState(!n),g=i.useRef(null);i.useImperativeHandle(e,()=>c,[c]),ye&&!U&&n&&(g.current=fe(M==null?void 0:M.document)),n&&T&&N(!1);const te=x(()=>{if(c.add(),O.current=we(document,"keydown",me),D.current=we(document,"focus",()=>setTimeout(ne),!0),W&&W(),I){var d,se;const V=fe((d=(se=c.dialog)==null?void 0:se.ownerDocument)!=null?d:M==null?void 0:M.document);c.dialog&&V&&!Me(c.dialog,V)&&(g.current=V,c.dialog.focus())}}),K=x(()=>{if(c.remove(),O.current==null||O.current(),D.current==null||D.current(),F){var d;(d=g.current)==null||d.focus==null||d.focus(v),g.current=null}});i.useEffect(()=>{!n||!B||te()},[n,B,te]),i.useEffect(()=>{T&&K()},[T,K]),Oe(()=>{K()});const ne=x(()=>{if(!w||!ee()||!c.isTopModal())return;const d=fe(M==null?void 0:M.document);c.dialog&&d&&!Me(c.dialog,d)&&c.dialog.focus()}),ue=x(d=>{d.target===d.currentTarget&&(E==null||E(d),u===!0&&Y())}),me=x(d=>{y&&lt(d)&&c.isTopModal()&&(h==null||h(d),d.defaultPrevented||Y())}),D=i.useRef(),O=i.useRef(),z=(...d)=>{N(!0),H==null||H(...d)};if(!B)return null;const oe=Object.assign({role:s,ref:c.setDialogRef,"aria-modal":s==="dialog"?!0:void 0},ce,{style:r,className:a,tabIndex:-1});let G=_?_(oe):o.jsx("div",Object.assign({},oe,{children:i.cloneElement(m,{role:"document"})}));G=xe(f,b,{unmountOnExit:!0,mountOnEnter:!0,appear:!0,in:!!n,onExit:P,onExiting:J,onExited:z,onEnter:Q,onEntering:Z,onEntered:de,children:G});let j=null;return u&&(j=re({ref:c.setBackdropRef,onClick:ue}),j=xe(R,k,{in:!!n,appear:!0,mountOnEnter:!0,unmountOnExit:!0,children:j})),o.jsx(o.Fragment,{children:Ye.createPortal(o.jsxs(o.Fragment,{children:[j,G]}),B)})});Se.displayName="Modal";const Ct=Object.assign(Se,{Manager:ve});function Rt(t,e){t.classList?t.classList.add(e):dt(t,e)||(typeof t.className=="string"?t.className=t.className+" "+e:t.setAttribute("class",(t.className&&t.className.baseVal||"")+" "+e))}function ke(t,e){return t.replace(new RegExp("(^|\\s)"+e+"(?:\\s|$)","g"),"$1").replace(/\s+/g," ").replace(/^\s*|\s*$/g,"")}function Tt(t,e){t.classList?t.classList.remove(e):typeof t.className=="string"?t.className=ke(t.className,e):t.setAttribute("class",ke(t.className&&t.className.baseVal||"",e))}const $={FIXED_CONTENT:".fixed-top, .fixed-bottom, .is-fixed, .sticky-top",STICKY_CONTENT:".sticky-top",NAVBAR_TOGGLER:".navbar-toggler"};class jt extends ve{adjustAndStore(e,n,s){const a=n.style[e];n.dataset[e]=a,X(n,{[e]:`${parseFloat(X(n,e))+s}px`})}restore(e,n){const s=n.dataset[e];s!==void 0&&(delete n.dataset[e],X(n,{[e]:s}))}setContainerStyle(e){super.setContainerStyle(e);const n=this.getElement();if(Rt(n,"modal-open"),!e.scrollBarWidth)return;const s=this.isRTL?"paddingLeft":"paddingRight",a=this.isRTL?"marginLeft":"marginRight";A(n,$.FIXED_CONTENT).forEach(r=>this.adjustAndStore(s,r,e.scrollBarWidth)),A(n,$.STICKY_CONTENT).forEach(r=>this.adjustAndStore(a,r,-e.scrollBarWidth)),A(n,$.NAVBAR_TOGGLER).forEach(r=>this.adjustAndStore(a,r,e.scrollBarWidth))}removeContainerStyle(e){super.removeContainerStyle(e);const n=this.getElement();Tt(n,"modal-open");const s=this.isRTL?"paddingLeft":"paddingRight",a=this.isRTL?"marginLeft":"marginRight";A(n,$.FIXED_CONTENT).forEach(r=>this.restore(s,r)),A(n,$.STICKY_CONTENT).forEach(r=>this.restore(a,r)),A(n,$.NAVBAR_TOGGLER).forEach(r=>this.restore(a,r))}}let ge;function kt(t){return ge||(ge=new jt(t)),ge}const Ae=i.forwardRef(({className:t,bsPrefix:e,as:n="div",...s},a)=>(e=L(e,"modal-body"),o.jsx(n,{ref:a,className:C(t,e),...s})));Ae.displayName="ModalBody";const _t=Ae,Bt=i.createContext({onHide(){}}),$e=Bt,Le=i.forwardRef(({bsPrefix:t,className:e,contentClassName:n,centered:s,size:a,fullscreen:r,children:m,scrollable:u,...y},E)=>{t=L(t,"modal");const h=`${t}-dialog`,f=typeof r=="string"?`${t}-fullscreen-${r}`:`${t}-fullscreen`;return o.jsx("div",{...y,ref:E,className:C(h,e,a&&`${t}-${a}`,s&&`${h}-centered`,u&&`${h}-scrollable`,r&&f),children:o.jsx("div",{className:C(`${t}-content`,n),children:m})})});Le.displayName="ModalDialog";const Ie=Le,Fe=i.forwardRef(({className:t,bsPrefix:e,as:n="div",...s},a)=>(e=L(e,"modal-footer"),o.jsx(n,{ref:a,className:C(t,e),...s})));Fe.displayName="ModalFooter";const Dt=Fe,Ot=i.forwardRef(({closeLabel:t="Close",closeVariant:e,closeButton:n=!1,onHide:s,children:a,...r},m)=>{const u=i.useContext($e),y=x(()=>{u==null||u.onHide(),s==null||s()});return o.jsxs("div",{ref:m,...r,children:[a,n&&o.jsx(ct,{"aria-label":t,variant:e,onClick:y})]})}),St=Ot,We=i.forwardRef(({bsPrefix:t,className:e,closeLabel:n="Close",closeButton:s=!1,...a},r)=>(t=L(t,"modal-header"),o.jsx(St,{ref:r,...a,className:C(e,t),closeLabel:n,closeButton:s})));We.displayName="ModalHeader";const At=We,$t=ht("h4"),He=i.forwardRef(({className:t,bsPrefix:e,as:n=$t,...s},a)=>(e=L(e,"modal-title"),o.jsx(n,{ref:a,className:C(t,e),...s})));He.displayName="ModalTitle";const Lt=He;function It(t){return o.jsx(De,{...t,timeout:null})}function Ft(t){return o.jsx(De,{...t,timeout:null})}const Ue=i.forwardRef(({bsPrefix:t,className:e,style:n,dialogClassName:s,contentClassName:a,children:r,dialogAs:m=Ie,"aria-labelledby":u,"aria-describedby":y,"aria-label":E,show:h=!1,animation:f=!0,backdrop:b=!0,keyboard:R=!0,onEscapeKeyDown:k,onShow:I,onHide:w,container:F,autoFocus:v=!0,enforceFocus:_=!0,restoreFocus:re=!0,restoreFocusOptions:ie,onEntered:le,onExit:W,onExiting:Y,onEnter:P,onEntering:H,onExited:J,backdropClassName:Q,manager:Z,...de},ce)=>{const[M,B]=i.useState({}),[c,ee]=i.useState(!1),U=i.useRef(!1),T=i.useRef(!1),N=i.useRef(null),[g,te]=st(),K=at(ce,te),ne=x(w),ue=Pe();t=L(t,"modal");const me=i.useMemo(()=>({onHide:ne}),[ne]);function D(){return Z||kt({isRTL:ue})}function O(l){if(!ye)return;const S=D().getScrollbarWidth()>0,be=l.scrollHeight>_e(l).documentElement.clientHeight;B({paddingRight:S&&!be?Te():void 0,paddingLeft:!S&&be?Te():void 0})}const z=x(()=>{g&&O(g.dialog)});Oe(()=>{Ne(window,"resize",z),N.current==null||N.current()});const oe=()=>{U.current=!0},G=l=>{U.current&&g&&l.target===g.dialog&&(T.current=!0),U.current=!1},j=()=>{ee(!0),N.current=ut(g.dialog,()=>{ee(!1)})},d=l=>{l.target===l.currentTarget&&j()},se=l=>{if(b==="static"){d(l);return}if(T.current||l.target!==l.currentTarget){T.current=!1;return}w==null||w()},V=l=>{R?k==null||k(l):(l.preventDefault(),b==="static"&&j())},Ke=(l,S)=>{l&&O(l),P==null||P(l,S)},ze=l=>{N.current==null||N.current(),W==null||W(l)},Ge=(l,S)=>{H==null||H(l,S),rt(window,"resize",z)},Ve=l=>{l&&(l.style.display=""),J==null||J(l),Ne(window,"resize",z)},qe=i.useCallback(l=>o.jsx("div",{...l,className:C(`${t}-backdrop`,Q,!f&&"show")}),[f,Q,t]),Ee={...n,...M};Ee.display="block";const Xe=l=>o.jsx("div",{role:"dialog",...l,style:Ee,className:C(e,t,c&&`${t}-static`,!f&&"show"),onClick:b?se:void 0,onMouseUp:G,"aria-label":E,"aria-labelledby":u,"aria-describedby":y,children:o.jsx(m,{...de,onMouseDown:oe,className:s,contentClassName:a,children:r})});return o.jsx($e.Provider,{value:me,children:o.jsx(Ct,{show:h,ref:K,backdrop:b,container:F,keyboard:!0,autoFocus:v,enforceFocus:_,restoreFocus:re,restoreFocusOptions:ie,onEscapeKeyDown:V,onShow:I,onHide:w,onEnter:Ke,onEntering:Ge,onEntered:le,onExit:ze,onExiting:Y,onExited:Ve,manager:D(),transition:f?It:void 0,backdropTransition:f?Ft:void 0,renderBackdrop:qe,renderDialog:Xe})})});Ue.displayName="Modal";const q=Object.assign(Ue,{Body:_t,Header:At,Title:Lt,Footer:Dt,Dialog:Ie,TRANSITION_DURATION:300,BACKDROP_TRANSITION_DURATION:150}),Wt="_title_z7kr5_1",Ht="_content_z7kr5_5",Ut="_buttons_z7kr5_9",pe={title:Wt,content:Ht,buttons:Ut},Kt=t=>o.jsxs(q,{show:t.visible,onHide:t.onClose,children:[o.jsx(q.Header,{closeButton:!0,children:o.jsx(q.Title,{className:pe.title,children:t.title})}),o.jsx(q.Body,{children:o.jsx("p",{className:pe.content,children:t.content})}),o.jsx(q.Footer,{className:pe.buttons,children:t.renderedButtons})]}),zt=(t,e,n)=>{const[s,a]=i.useState(!1),r=()=>{a(!1)},m=o.jsx(Kt,{title:t,content:e,visible:s,renderedButtons:n(r),onClose:r});return[Je.createPortal(m,document.getElementById("modal")),a]},Gt="_group_1lcw4_1",Vt="_info_1lcw4_9",qt="_body_1lcw4_31",Xt="_buttons_1lcw4_36",Yt="_description_1lcw4_67",Pt="_col_1lcw4_70",Jt="_title_1lcw4_77",p={group:Gt,info:Vt,"image-wrapper":"_image-wrapper_1lcw4_22","loading-image":"_loading-image_1lcw4_28",body:qt,buttons:Xt,description:Yt,col:Pt,title:Jt},cn=o.jsx("h2",{children:"Hmmm... we couldn't find that image..."});function un(){const t=Qe(),n=new URLSearchParams(t.search).get("id"),s=Ze(),a=et(),r=gt(n),[m,u]=zt("Delete Image","Are you sure you want to delete this image?",v=>o.jsxs(o.Fragment,{children:[o.jsx(Re,{className:"btn btn-lg btn-warning",onClick:v,children:"Cancel"}),o.jsx(Re,{className:"btn btn-lg btn-danger",onClick:()=>{h(),v()},children:"Delete"})]})),[y]=pt({id:+n,title:"title"in r.payload?r.payload.title:"",wrapperClassName:`card-img ${p["image-wrapper"]}`,defaultImageShouldLoad:!0,imageClassName:p.image,loadingImageClassName:p["loading-image"]});if(r.type==="COMPONENT")return r.payload;const E=()=>{s("/")},h=async()=>{await fetch(`${tt}/delete?id=${n}`,nt("DELETE")),a({type:"DELETE_IMAGE_ITEM",payload:+n}),E()},f=()=>{u(!0)},b=()=>{s(`/update?id=${n}`)},R=r.payload,{title:k,description:I}=R,w=I.split(`
`).map((v,_)=>o.jsxs("li",{children:[v," ",o.jsx("br",{})]},`${v}__${_}`)),F=new Date(R.date).toLocaleDateString();return o.jsxs(Ce,{className:p.group,children:[m,o.jsx(Ce,{className:`row ${p.body}`,children:o.jsxs("div",{className:`${p.info} ${p.col}`,children:[y,o.jsx("h1",{className:`card-title text-center ${p.title}`,children:k}),o.jsx("div",{className:"container",children:o.jsxs("div",{className:"row my-4",children:[o.jsx("div",{className:"col-md-6",children:o.jsxs("p",{children:["Uploaded: ",F]})}),o.jsx("div",{className:"col-md-6",children:o.jsxs("p",{children:["Category: ",R.category]})})]})}),o.jsx("ul",{className:p.description,children:w})]})}),o.jsxs(yt,{className:p.buttons,children:[o.jsx("button",{className:"btn btn-lg btn-primary",onClick:b,children:"Edit"}),o.jsx("button",{className:"btn btn-lg btn-danger",onClick:f,children:"Delete"})]})]})}export{un as default,cn as errorComponent};
