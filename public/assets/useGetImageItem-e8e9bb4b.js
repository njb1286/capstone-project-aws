import{r as s,f as I,i as g,g as l,h as E,j as i,L as d}from"./index-0d223769.js";function h(e){const[m,r]=s.useState(!1),[n,u]=s.useState(null),o=s.useRef(!1),f=I(),c=g(t=>t.imageItems);s.useEffect(()=>{if(o.current)return;if(o.current=!0,!e){r(!0);return}const t=c.find(a=>a.id===+e);if(t){u(t);return}p()},[c,e]);async function p(){try{const t=await fetch(`${l}/get?id=${e}`,E("GET"));if(t.status>299){r(!0);return}const a=await t.json();f({type:"ADD_IMAGE_ITEM",payload:a}),u(a)}catch{r(!0)}}return m?{type:"COMPONENT",payload:i.jsx("h2",{children:"Hmmm... we couldn't find that image..."})}:n?{type:"IMAGE_ITEM",payload:n}:{type:"COMPONENT",payload:i.jsx(d,{})}}export{h as u};
