import{f as g,g as f,k as y,r as I,h as E,i as h}from"./index-98d0db0e.js";import{u as M}from"./useUploadForm-bbe7aa57.js";import{u as P}from"./useGetImageItem-1f4c703a.js";import"./Form-a7b8b861.js";import"./index-7d457e60.js";import"./FormCheckInput-05cdc6ad.js";import"./DropDown-c5752ff2.js";import"./useWindow-304bdbfd.js";import"./Button-24167188.js";import"./ButtonGroup-1bc4954d.js";function N(){const p=g(),n=f(),t=new URLSearchParams(location.search).get("id"),r=y(o=>t?o.imageItems.find(i=>i.id===+t):void 0),e=P(t),[d,m,c]=M({id:+t,onSubmit:u,updating:!0,title:e.type==="IMAGE_ITEM"?e.payload.title:"",description:e.type==="IMAGE_ITEM"?e.payload.description:"",category:e.type==="IMAGE_ITEM"?e.payload.category:"Other"});if(I.useEffect(()=>{r&&c(r.title,r.description,r.category)},[r]),e.type==="COMPONENT")return e.payload;async function u(o,i,l,s){const a=new FormData;if(a.append("image",l),a.append("title",o),a.append("description",i),a.append("id",t),a.append("category",s),(await fetch(`${E}/update?id=${t}`,{body:a,...h("POST")})).status>299){m();return}n({type:"UPDATE_IMAGE_ITEM",payload:{id:+t,title:o,description:i,category:s}}),p(`/views?id=${t}`)}return d}export{N as default};
