import{r,j as n,c as d,u,n as W,o as X}from"./index-0d223769.js";import{P as N}from"./index-42e6a327.js";import{a as $,F as T}from"./FormCheckInput-132a99e2.js";function Y(e,o){return r.Children.toArray(e).some(s=>r.isValidElement(s)&&s.type===o)}function Z({as:e,bsPrefix:o,className:s,...a}){o=u(o,"col");const t=W(),l=X(),c=[],i=[];return t.forEach(p=>{const m=a[p];delete a[p];let f,h,y;typeof m=="object"&&m!=null?{span:f,offset:h,order:y}=m:f=m;const F=p!==l?`-${p}`:"";f&&c.push(f===!0?`${o}${F}`:`${o}${F}-${f}`),y!=null&&i.push(`order${F}-${y}`),h!=null&&i.push(`offset${F}-${h}`)}),[{...a,className:d(s,...c,...i)},{as:e,bsPrefix:o,spans:c}]}const I=r.forwardRef((e,o)=>{const[{className:s,...a},{as:t="div",bsPrefix:l,spans:c}]=Z(e);return n.jsx(t,{...a,ref:o,className:d(s,!c.length&&l)})});I.displayName="Col";const P=I,ee={type:N.string,tooltip:N.bool,as:N.elementType},R=r.forwardRef(({as:e="div",className:o,type:s="valid",tooltip:a=!1,...t},l)=>n.jsx(e,{...t,ref:l,className:d(o,`${s}-${a?"tooltip":"feedback"}`)}));R.displayName="Feedback";R.propTypes=ee;const B=R,O=r.forwardRef(({bsPrefix:e,className:o,htmlFor:s,...a},t)=>{const{controlId:l}=r.useContext($);return e=u(e,"form-check-label"),n.jsx("label",{...a,ref:t,htmlFor:s||l,className:d(o,e)})});O.displayName="FormCheckLabel";const v=O,S=r.forwardRef(({id:e,bsPrefix:o,bsSwitchPrefix:s,inline:a=!1,reverse:t=!1,disabled:l=!1,isValid:c=!1,isInvalid:i=!1,feedbackTooltip:p=!1,feedback:m,feedbackType:f,className:h,style:y,title:F="",type:C="checkbox",label:g,children:w,as:H="input",...J},K)=>{o=u(o,"form-check"),s=u(s,"form-switch");const{controlId:x}=r.useContext($),Q=r.useMemo(()=>({controlId:e||x}),[x,e]),L=!w&&g!=null&&g!==!1||Y(w,v),U=n.jsx(T,{...J,type:C==="switch"?"checkbox":C,ref:K,isValid:c,isInvalid:i,disabled:l,as:H});return n.jsx($.Provider,{value:Q,children:n.jsx("div",{style:y,className:d(h,L&&o,a&&`${o}-inline`,t&&`${o}-reverse`,C==="switch"&&s),children:w||n.jsxs(n.Fragment,{children:[U,L&&n.jsx(v,{title:F,children:g}),m&&n.jsx(B,{type:f,tooltip:p,children:m})]})})})});S.displayName="FormCheck";const j=Object.assign(S,{Input:T,Label:v}),b=r.forwardRef(({bsPrefix:e,type:o,size:s,htmlSize:a,id:t,className:l,isValid:c=!1,isInvalid:i=!1,plaintext:p,readOnly:m,as:f="input",...h},y)=>{const{controlId:F}=r.useContext($);return e=u(e,"form-control"),n.jsx(f,{...h,type:o,size:a,ref:y,readOnly:m,id:t||F,className:d(l,p?`${e}-plaintext`:e,s&&`${e}-${s}`,o==="color"&&`${e}-color`,c&&"is-valid",i&&"is-invalid")})});b.displayName="FormControl";const oe=Object.assign(b,{Feedback:B}),E=r.forwardRef(({className:e,bsPrefix:o,as:s="div",...a},t)=>(o=u(o,"form-floating"),n.jsx(s,{ref:t,className:d(e,o),...a})));E.displayName="FormFloating";const se=E,G=r.forwardRef(({controlId:e,as:o="div",...s},a)=>{const t=r.useMemo(()=>({controlId:e}),[e]);return n.jsx($.Provider,{value:t,children:n.jsx(o,{...s,ref:a})})});G.displayName="FormGroup";const M=G,V=r.forwardRef(({as:e="label",bsPrefix:o,column:s=!1,visuallyHidden:a=!1,className:t,htmlFor:l,...c},i)=>{const{controlId:p}=r.useContext($);o=u(o,"form-label");let m="col-form-label";typeof s=="string"&&(m=`${m} ${m}-${s}`);const f=d(t,o,a&&"visually-hidden",s&&m);return l=l||p,s?n.jsx(P,{ref:i,as:"label",className:f,htmlFor:l,...c}):n.jsx(e,{ref:i,className:f,htmlFor:l,...c})});V.displayName="FormLabel";const ae=V,A=r.forwardRef(({bsPrefix:e,className:o,id:s,...a},t)=>{const{controlId:l}=r.useContext($);return e=u(e,"form-range"),n.jsx("input",{...a,type:"range",ref:t,className:d(o,e),id:s||l})});A.displayName="FormRange";const te=A,_=r.forwardRef(({bsPrefix:e,size:o,htmlSize:s,className:a,isValid:t=!1,isInvalid:l=!1,id:c,...i},p)=>{const{controlId:m}=r.useContext($);return e=u(e,"form-select"),n.jsx("select",{...i,size:s,ref:p,className:d(a,e,o&&`${e}-${o}`,t&&"is-valid",l&&"is-invalid"),id:c||m})});_.displayName="FormSelect";const le=_,q=r.forwardRef(({bsPrefix:e,className:o,as:s="small",muted:a,...t},l)=>(e=u(e,"form-text"),n.jsx(s,{...t,ref:l,className:d(o,e,a&&"text-muted")})));q.displayName="FormText";const re=q,z=r.forwardRef((e,o)=>n.jsx(j,{...e,ref:o,type:"switch"}));z.displayName="Switch";const ne=Object.assign(z,{Input:j.Input,Label:j.Label}),D=r.forwardRef(({bsPrefix:e,className:o,children:s,controlId:a,label:t,...l},c)=>(e=u(e,"form-floating"),n.jsxs(M,{ref:c,className:d(o,e),controlId:a,...l,children:[s,n.jsx("label",{htmlFor:a,children:t})]})));D.displayName="FloatingLabel";const ce=D,me={_ref:N.any,validated:N.bool,as:N.elementType},k=r.forwardRef(({className:e,validated:o,as:s="form",...a},t)=>n.jsx(s,{...a,ref:t,className:d(e,o&&"was-validated")}));k.displayName="Form";k.propTypes=me;const fe=Object.assign(k,{Group:M,Control:oe,Floating:se,Check:j,Switch:ne,Label:ae,Text:re,Range:te,Select:le,FloatingLabel:ce});export{fe as F,oe as a,M as b};
