import{f as d,g as r,h as i,e as f}from"./index-6523de4f.js";import{u as g}from"./useUploadForm-170e2a83.js";import"./Form-d63cde17.js";import"./index-a3d930ca.js";import"./FormCheckInput-427c7d16.js";import"./DropDown-8fbe49a2.js";import"./DataKey-47834c0e.js";import"./useWindow-c93d28bb.js";import"./mergeOptionsWithPopperConfig-2ac09cac.js";import"./Button-984d1bdd.js";import"./ButtonGroup-1d4cacf8.js";const l=async t=>{const a=await fetch(`${r}/get?id=${t}`,i("GET"));return a.status>=299?null:await a.json()},I=async()=>{const t=await fetch(`${r}/last`,i("GET"));return t.status>=299?null:await t.json()},y=()=>{const t=d();return async e=>{if(e){const o=await l(e);if(!o)return;t({type:"ADD_IMAGE_ITEM",payload:o})}const n=await I();n&&t({type:"ADD_IMAGE_ITEM",payload:n})}};function U(){const t=f(),a=y();async function e(p,m,c,u){const s=new FormData;if(s.append("image",c),s.append("title",p),s.append("description",m),s.append("category",u),(await fetch(`${r}/form`,{body:s,...i("POST")})).status>299){o();return}a(),t("/")}const[n,o]=g({updating:!1,onSubmit:e});return n}export{U as default};
