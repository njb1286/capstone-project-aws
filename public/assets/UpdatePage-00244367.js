import{f as g,g as f,k as y,r as I,h as E,i as h}from"./index-924502c0.js";import{u as M}from"./useUploadForm-4e23015d.js";import{u as P}from"./useGetImageItem-52e1e59e.js";import"./Form-05c8fb96.js";import"./index-361841d5.js";import"./FormCheckInput-819bf322.js";import"./DropDown-d34b0528.js";import"./useWindow-76793841.js";import"./Button-527a8964.js";import"./ButtonGroup-eee1b67d.js";function N(){const p=g(),n=f(),t=new URLSearchParams(location.search).get("id"),r=y(o=>t?o.imageItems.find(i=>i.id===+t):void 0),e=P(t),[d,m,c]=M({id:+t,onSubmit:u,updating:!0,title:e.type==="IMAGE_ITEM"?e.payload.title:"",description:e.type==="IMAGE_ITEM"?e.payload.description:"",category:e.type==="IMAGE_ITEM"?e.payload.category:"Other"});if(I.useEffect(()=>{r&&c(r.title,r.description,r.category)},[r]),e.type==="COMPONENT")return e.payload;async function u(o,i,l,s){const a=new FormData;if(a.append("image",l),a.append("title",o),a.append("description",i),a.append("id",t),a.append("category",s),(await fetch(`${E}/update?id=${t}`,{body:a,...h("POST")})).status>299){m();return}n({type:"UPDATE_IMAGE_ITEM",payload:{id:+t,title:o,description:i,category:s}}),p(`/views?id=${t}`)}return d}export{N as default};
