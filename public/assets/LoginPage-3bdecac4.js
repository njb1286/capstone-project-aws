import{r as o,g as h,j as s,S as g,h as x,m as b,s as j}from"./index-5f75a154.js";import{C as S}from"./Container-b8f286db.js";import{F as a}from"./Form-c33f40e4.js";import{B as _}from"./Button-1ddd24fe.js";import"./index-520c09bc.js";import"./FormCheckInput-291adace.js";const w="_group_z9u5n_1",y="_button_z9u5n_6",k="_form_z9u5n_10",n={group:w,button:y,form:k},z=()=>{const[t,i]=o.useState(!1),[u,c]=o.useState(!1),d=h(),[l,m]=o.useState(""),p=async e=>{e.preventDefault(),c(!1),i(!0);const r=await(await fetch(`${x}/login`,{method:"POST",headers:{password:l,token:b()??""}})).json();if(i(!1),m(""),"token"in r){j(r.token),d({type:"SET_TOKEN",payload:r.token});return}c(!0)},f=e=>{m(e.target.value)};return s.jsx(S,{fluid:!0,className:"d-flex align-items-center justify-content-center",style:{height:"100vh"},children:s.jsxs(a,{onSubmit:p,className:n.form,children:[s.jsxs(a.Group,{className:n.group,controlId:"formPassword",children:[s.jsx("h2",{className:"text-center",children:"Password"}),s.jsx(a.Control,{value:l,onChange:f,disabled:t,type:"password",placeholder:"Enter password"}),u&&s.jsx("p",{className:"text-danger fs-3",children:"Incorrect password!"})]}),t&&s.jsx(g,{variant:"primary",animation:"border"}),s.jsx(_,{className:n.button,variant:"primary",type:"submit",disabled:t,children:"Login"})]})})};export{z as default};
