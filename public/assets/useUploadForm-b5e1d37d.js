import{r as u,j as t,e as q,k,S as z}from"./index-a65ce320.js";import{F as l,a as v,b as _}from"./Form-d3eb778c.js";import{D as J}from"./DropDown-bb59d359.js";import{B as K}from"./ButtonGroup-57c478c3.js";import{B as D}from"./Button-dc07e095.js";const Q="_btn_1ih27_11",W="_buttons_1ih27_16",X="_spinner_1ih27_20",Y="_visible_1ih27_23",Z="_submit_1ih27_34",P="_dropdown_1ih27_41",ee="_categories_1ih27_48",o={"form-items":"_form-items_1ih27_1","upload-form":"_upload-form_1ih27_5",btn:Q,buttons:W,spinner:X,visible:Y,submit:Z,dropdown:P,categories:ee,"category-item":"_category-item_1ih27_53"};function te(a,r){switch(r.type){case"SET_IS_VALID":return{...a,isValid:r.payload};case"SET_TOUCHED":return{...a,touched:r.payload};case"SET_VALUE":return{...a,value:r.payload};case"SET_ERROR_MESSAGE":return{...a,errorMessage:r.payload};default:return a}}function S(a,r,m,p,c){const[s,n]=u.useReducer(te,m),f=i=>{n({type:"SET_VALUE",payload:p(i)})},y=()=>{n({type:"SET_TOUCHED",payload:!0});const i=c(s.value);n({type:"SET_IS_VALID",payload:!i}),typeof i!=typeof s.errorMessage&&i!==s.errorMessage&&n({type:"SET_ERROR_MESSAGE",payload:i})},d=()=>{n({type:"SET_TOUCHED",payload:!1})},b=i=>{n({type:"SET_TOUCHED",payload:i})},g=i=>{n({type:"SET_IS_VALID",payload:i})},E=i=>{n({type:"SET_VALUE",payload:i})};return[t.jsxs(t.Fragment,{children:[t.jsx(a,{onBlur:y,onFocus:d,onChange:f,isValid:s.isValid&&s.touched,isInvalid:!s.isValid&&s.touched,defaultValue:typeof s.value=="string"||typeof s.value=="number"?s.value:void 0,...r,as:r.as}),t.jsx(l.Label,{style:{visibility:s.touched&&!s.isValid?"visible":"hidden"},className:"text-danger",children:s.errorMessage??"valid"})]}),!c(s.value),s.value,b,g,E]}function le(a){const[r,m]=u.useState(!1),[p,c]=u.useState(a.category??"Other"),[s,n]=u.useState(!1),f=q(),y=e=>{if(e.preventDefault(),!g||!x||!T){V.forEach(h=>h(!0));return}m(!0),a.onSubmit(E,L,M,p)};function d(e){return{touched:!1,isValid:!1,value:e,errorMessage:void 0}}const[b,g,E,j,i,I]=S(v,{as:"input"},d(a.title??""),e=>e.target.value,e=>{if(e.length===0)return"Title is required"}),[C,x,L,F,N,A]=S(v,{as:"textarea",style:{height:"300px"}},d(a.description??""),e=>e.target.value,e=>{if(e.length===0)return"Description is required"}),[H,T,M,R,U]=S(v,{type:"file",accept:"image/png, image/jpeg, image/jpg"},d(null),e=>e.target.files[0],e=>{if(!e)return a.updating?void 0:"Image is required";if(!["image/png","image/jpeg","image/jpg"].includes(e.type))return"Image must be a png, jpeg, or jpg"}),V=[j,F,R],w=[i,N,U];u.useEffect(()=>{a.updating===!0&&(w.forEach(e=>e(!0)),V.forEach(e=>e(!0)))},[]);const O=()=>{n(!0),m(!1)},B=(e,h,G)=>{I(e),A(h),c(G)},$=t.jsx("p",{className:"text-danger",children:"An error occurred!"});return[t.jsxs("div",{className:o["upload-form"],children:[t.jsxs(l,{onSubmit:y,children:[t.jsxs("div",{className:o["form-items"],children:[t.jsxs(_,{children:[t.jsx(l.Label,{children:"Title"}),b]}),t.jsxs(_,{children:[t.jsx(l.Label,{children:"Image"}),H]}),t.jsxs(_,{children:[t.jsx(l.Label,{children:"Description"}),C]}),t.jsxs(_,{children:[t.jsx(l.Label,{children:"Category"}),t.jsx(J,{className:o.dropdown,onSelect:c,categories:k,default:p})]})]}),t.jsx(z,{className:`${o.spinner} ${r?o.visible:""}`,variant:"primary",animation:"border"}),t.jsxs(K,{className:o.buttons,children:[t.jsx(D,{disabled:!g||!x||!T||r,className:o.btn,type:"submit",children:"Submit"}),a.updating&&t.jsx(D,{className:`${o.btn} btn-danger`,type:"button",onClick:()=>f(`/views?id=${a.id}`),children:"Cancel"})]})]}),s&&$]}),O,B]}export{le as u};
