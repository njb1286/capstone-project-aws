import{r as t,f as b,j as s,S as w,g as S,l as j,s as _}from"./index-31c29614.js";import{C as k}from"./Container-7fad3ca1.js";import{F as a}from"./Form-8a69873c.js";import{B as y}from"./Button-0b059426.js";import"./index-aca23684.js";import"./FormCheckInput-ec6021fd.js";const N="_group_h51hd_1",E="_button_h51hd_6",v="_form_h51hd_10",o={group:N,button:E,form:v,switch:"_switch_h51hd_20"},D=()=>{const[r,i]=t.useState(!1),[u,c]=t.useState(!1),h=b(),[l,d]=t.useState(""),[p,m]=t.useState(!1),g=async e=>{e.preventDefault(),c(!1),i(!0);const n=await(await fetch(`${S}/login`,{method:"POST",headers:{password:l,token:j()??"",singleUse:p.toString()}})).json();if(i(!1),d(""),"token"in n){_(n.token),h({type:"SET_TOKEN",payload:n.token});return}c(!0)},f=e=>{d(e.target.value)},x=()=>{m(e=>!e)};return s.jsx(k,{fluid:!0,className:"d-flex align-items-center justify-content-center",style:{height:"100vh"},children:s.jsxs(a,{onSubmit:g,className:o.form,children:[s.jsxs(a.Group,{className:o.group,controlId:"formPassword",children:[s.jsx("h2",{className:"text-center",children:"Password"}),s.jsx(a.Control,{value:l,onChange:f,disabled:r,type:"password",placeholder:"Enter password"}),s.jsx(a.Check,{type:"checkbox",label:"Single-use password",checked:p,onChange:x,className:o.switch,id:"single-use-password-input"}),u&&s.jsx("p",{className:"text-danger fs-3",children:"Incorrect password!"})]}),r&&s.jsx(w,{variant:"primary",animation:"border"}),s.jsx(y,{className:o.button,variant:"primary",type:"submit",disabled:r,children:"Login"})]})})};export{D as default};
