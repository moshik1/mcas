(window.webpackJsonp=window.webpackJsonp||[]).push([[28],{"J3+z":function(e,t,a){"use strict";a.r(t),a.d(t,"_frontmatter",(function(){return i})),a.d(t,"default",(function(){return d}));a("91GP"),a("rGqo"),a("yt8O"),a("Btvt"),a("RW0V"),a("q1tI");var n=a("7ljp"),c=a("013z");a("qKvR");function l(){return(l=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var a=arguments[t];for(var n in a)Object.prototype.hasOwnProperty.call(a,n)&&(e[n]=a[n])}return e}).apply(this,arguments)}var i={},r=function(e){return function(t){return console.warn("Component "+e+" was not imported, exported, or provided by MDXProvider as global scope"),Object(n.b)("div",t)}},b=r("PageDescription"),m=r("Title"),p=r("Row"),s=r("Column"),o={_frontmatter:i},g=c.a;function d(e){var t=e.components,a=function(e,t){if(null==e)return{};var a,n,c={},l=Object.keys(e);for(n=0;n<l.length;n++)a=l[n],t.indexOf(a)>=0||(c[a]=e[a]);return c}(e,["components"]);return Object(n.b)(g,l({},o,a,{components:t,mdxType:"MDXLayout"}),Object(n.b)(b,{mdxType:"PageDescription"},Object(n.b)("p",null,Object(n.b)("inlineCode",{parentName:"p"},"<Row>")," and ",Object(n.b)("inlineCode",{parentName:"p"},"<Column>")," components are used to arrange content and components on the grid within a page.\nTo learn more about the grid is built, you can read the docs in the ",Object(n.b)("a",l({parentName:"p"},{href:"https://github.com/carbon-design-system/carbon/tree/master/packages/grid"}),"Carbon")," repo.")),Object(n.b)("h2",null,"Row"),Object(n.b)("p",null,"The ",Object(n.b)("inlineCode",{parentName:"p"},"<Row>")," component is a wrapper that adds the ",Object(n.b)("inlineCode",{parentName:"p"},"bx--row")," class to a wrapper div. You will want to use this to define rows that you will place ",Object(n.b)("inlineCode",{parentName:"p"},"<Column>")," components inside of."),Object(n.b)("h3",null,"Code"),Object(n.b)("pre",null,Object(n.b)("code",l({parentName:"pre"},{className:"language-jsx",metastring:"path=components/Grid.js src=https://github.com/carbon-design-system/gatsby-theme-carbon/tree/master/packages/gatsby-theme-carbon/src/components/Grid",path:"components/Grid.js",src:"https://github.com/carbon-design-system/gatsby-theme-carbon/tree/master/packages/gatsby-theme-carbon/src/components/Grid"}),"<Row>\n  <Column>\n    Content or additional <Components />\n  </Column>\n</Row>\n")),Object(n.b)(m,{mdxType:"Title"},"Row props"),Object(n.b)("table",null,Object(n.b)("thead",{parentName:"table"},Object(n.b)("tr",{parentName:"thead"},Object(n.b)("th",l({parentName:"tr"},{align:null}),"property"),Object(n.b)("th",l({parentName:"tr"},{align:null}),"propType"),Object(n.b)("th",l({parentName:"tr"},{align:null}),"required"),Object(n.b)("th",l({parentName:"tr"},{align:null}),"default"),Object(n.b)("th",l({parentName:"tr"},{align:null}),"description"))),Object(n.b)("tbody",{parentName:"table"},Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"children"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"node"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}))),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"className"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"string"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Add custom class name")))),Object(n.b)("h2",null,"Column"),Object(n.b)("p",null,"The ",Object(n.b)("inlineCode",{parentName:"p"},"<Column>")," component is used to define column widths for your content, you can set the rules at different breakpoints with the props."),Object(n.b)("h3",null,"Example"),Object(n.b)(p,{mdxType:"Row"},Object(n.b)(s,{colMd:4,colLg:4,mdxType:"Column"},Object(n.b)("span",{className:"gatsby-resp-image-wrapper",style:{position:"relative",display:"block",marginLeft:"auto",marginRight:"auto",maxWidth:"1152px"}},"\n      ",Object(n.b)("span",l({parentName:"span"},{className:"gatsby-resp-image-background-image",style:{paddingBottom:"56.25%",position:"relative",bottom:"0",left:"0",backgroundImage:"url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAALCAYAAAB/Ca1DAAAACXBIWXMAAAsSAAALEgHS3X78AAACB0lEQVQoz12TS2/aQBRGWTTbqDie8fghSIRpkiJCgrBE8WvGNlRNaVTaLtquiyJ2CAK/qFIX/ZFf7xhDaBZHd2RrztxvHjVmmrhoXaJ79w5MeOB2A5bTPMDcFhzHRTgaIY6ikjAMkecZfv74jq9fZoii8ECNMYZmo4G311doNhsQFodh1HF2ZuwwXsO2BeI0gyw+IKGqUfkYHz99xv3DN8RxQjJaLI5RM6lD3/cRBAF6vVuih263W3GDTqcD13EQJRnSbIJUjUtBnEhaJEeiJjR+KWy3keUFpKKVsxxKV6VQFPRNSnieS0JVTtAyWdyT/D3FD5HIjITpsZDBb50jTwKoaEAEJElK0XA4xGAwgOdqoaSoshQkqaqqrIRHHXLTgNu6RTt5hB/PiV+4vgloTy/pMBxwzmELgYjiyfGUBAVFVSU6rpw8/C+0zFPU22O8Kv7iJP+Dk+w36l4XpnFKMguWZVFkDwnF0lsipUJakeV5WfeyXYc0weIMgtUhuFFiWQJC2GDMRL/fx3Q6xXK5xNN6jdVqhc3mCdvtFvP5HJl6Fupa0zLmXIB5V+Ud1DDvDbjrg9F2HAvXJNxsNlgsFpjNZqVE38m9bBeZhKXIOQcXLrhFnemxvuD07zny7qA0erI+sOPODpF3wiZ0dP0qmNumsaiEnGLTodg2RvRSouqV7Ce/lGn+AcEOYKn+FnaEAAAAAElFTkSuQmCC')",backgroundSize:"cover",display:"block"}})),"\n  ",Object(n.b)("img",l({parentName:"span"},{className:"gatsby-resp-image-image",alt:"Grid Example",title:"Grid Example",src:"/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png",srcSet:["/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/7fc1e/Article_05.png 288w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/a5df1/Article_05.png 576w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png 1152w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/362ee/Article_05.png 1600w"],sizes:"(max-width: 1152px) 100vw, 1152px",style:{width:"100%",height:"100%",margin:"0",verticalAlign:"middle",position:"absolute",top:"0",left:"0"},loading:"lazy"})),"\n    ")),Object(n.b)(s,{colMd:4,colLg:4,mdxType:"Column"},Object(n.b)("span",{className:"gatsby-resp-image-wrapper",style:{position:"relative",display:"block",marginLeft:"auto",marginRight:"auto",maxWidth:"1152px"}},"\n      ",Object(n.b)("span",l({parentName:"span"},{className:"gatsby-resp-image-background-image",style:{paddingBottom:"56.25%",position:"relative",bottom:"0",left:"0",backgroundImage:"url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAALCAYAAAB/Ca1DAAAACXBIWXMAAAsSAAALEgHS3X78AAACB0lEQVQoz12TS2/aQBRGWTTbqDie8fghSIRpkiJCgrBE8WvGNlRNaVTaLtquiyJ2CAK/qFIX/ZFf7xhDaBZHd2RrztxvHjVmmrhoXaJ79w5MeOB2A5bTPMDcFhzHRTgaIY6ikjAMkecZfv74jq9fZoii8ECNMYZmo4G311doNhsQFodh1HF2ZuwwXsO2BeI0gyw+IKGqUfkYHz99xv3DN8RxQjJaLI5RM6lD3/cRBAF6vVuih263W3GDTqcD13EQJRnSbIJUjUtBnEhaJEeiJjR+KWy3keUFpKKVsxxKV6VQFPRNSnieS0JVTtAyWdyT/D3FD5HIjITpsZDBb50jTwKoaEAEJElK0XA4xGAwgOdqoaSoshQkqaqqrIRHHXLTgNu6RTt5hB/PiV+4vgloTy/pMBxwzmELgYjiyfGUBAVFVSU6rpw8/C+0zFPU22O8Kv7iJP+Dk+w36l4XpnFKMguWZVFkDwnF0lsipUJakeV5WfeyXYc0weIMgtUhuFFiWQJC2GDMRL/fx3Q6xXK5xNN6jdVqhc3mCdvtFvP5HJl6Fupa0zLmXIB5V+Ud1DDvDbjrg9F2HAvXJNxsNlgsFpjNZqVE38m9bBeZhKXIOQcXLrhFnemxvuD07zny7qA0erI+sOPODpF3wiZ0dP0qmNumsaiEnGLTodg2RvRSouqV7Ce/lGn+AcEOYKn+FnaEAAAAAElFTkSuQmCC')",backgroundSize:"cover",display:"block"}})),"\n  ",Object(n.b)("img",l({parentName:"span"},{className:"gatsby-resp-image-image",alt:"Grid Example",title:"Grid Example",src:"/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png",srcSet:["/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/7fc1e/Article_05.png 288w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/a5df1/Article_05.png 576w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png 1152w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/362ee/Article_05.png 1600w"],sizes:"(max-width: 1152px) 100vw, 1152px",style:{width:"100%",height:"100%",margin:"0",verticalAlign:"middle",position:"absolute",top:"0",left:"0"},loading:"lazy"})),"\n    ")),Object(n.b)(s,{colMd:4,colLg:4,mdxType:"Column"},Object(n.b)("span",{className:"gatsby-resp-image-wrapper",style:{position:"relative",display:"block",marginLeft:"auto",marginRight:"auto",maxWidth:"1152px"}},"\n      ",Object(n.b)("span",l({parentName:"span"},{className:"gatsby-resp-image-background-image",style:{paddingBottom:"56.25%",position:"relative",bottom:"0",left:"0",backgroundImage:"url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAALCAYAAAB/Ca1DAAAACXBIWXMAAAsSAAALEgHS3X78AAACB0lEQVQoz12TS2/aQBRGWTTbqDie8fghSIRpkiJCgrBE8WvGNlRNaVTaLtquiyJ2CAK/qFIX/ZFf7xhDaBZHd2RrztxvHjVmmrhoXaJ79w5MeOB2A5bTPMDcFhzHRTgaIY6ikjAMkecZfv74jq9fZoii8ECNMYZmo4G311doNhsQFodh1HF2ZuwwXsO2BeI0gyw+IKGqUfkYHz99xv3DN8RxQjJaLI5RM6lD3/cRBAF6vVuih263W3GDTqcD13EQJRnSbIJUjUtBnEhaJEeiJjR+KWy3keUFpKKVsxxKV6VQFPRNSnieS0JVTtAyWdyT/D3FD5HIjITpsZDBb50jTwKoaEAEJElK0XA4xGAwgOdqoaSoshQkqaqqrIRHHXLTgNu6RTt5hB/PiV+4vgloTy/pMBxwzmELgYjiyfGUBAVFVSU6rpw8/C+0zFPU22O8Kv7iJP+Dk+w36l4XpnFKMguWZVFkDwnF0lsipUJakeV5WfeyXYc0weIMgtUhuFFiWQJC2GDMRL/fx3Q6xXK5xNN6jdVqhc3mCdvtFvP5HJl6Fupa0zLmXIB5V+Ud1DDvDbjrg9F2HAvXJNxsNlgsFpjNZqVE38m9bBeZhKXIOQcXLrhFnemxvuD07zny7qA0erI+sOPODpF3wiZ0dP0qmNumsaiEnGLTodg2RvRSouqV7Ce/lGn+AcEOYKn+FnaEAAAAAElFTkSuQmCC')",backgroundSize:"cover",display:"block"}})),"\n  ",Object(n.b)("img",l({parentName:"span"},{className:"gatsby-resp-image-image",alt:"Grid Example",title:"Grid Example",src:"/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png",srcSet:["/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/7fc1e/Article_05.png 288w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/a5df1/Article_05.png 576w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png 1152w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/362ee/Article_05.png 1600w"],sizes:"(max-width: 1152px) 100vw, 1152px",style:{width:"100%",height:"100%",margin:"0",verticalAlign:"middle",position:"absolute",top:"0",left:"0"},loading:"lazy"})),"\n    "))),Object(n.b)(m,{mdxType:"Title"},"No gutter left"),Object(n.b)(p,{mdxType:"Row"},Object(n.b)(s,{colMd:4,colLg:4,noGutterMdLeft:!0,mdxType:"Column"},Object(n.b)("span",{className:"gatsby-resp-image-wrapper",style:{position:"relative",display:"block",marginLeft:"auto",marginRight:"auto",maxWidth:"1152px"}},"\n      ",Object(n.b)("span",l({parentName:"span"},{className:"gatsby-resp-image-background-image",style:{paddingBottom:"56.25%",position:"relative",bottom:"0",left:"0",backgroundImage:"url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAALCAYAAAB/Ca1DAAAACXBIWXMAAAsSAAALEgHS3X78AAACB0lEQVQoz12TS2/aQBRGWTTbqDie8fghSIRpkiJCgrBE8WvGNlRNaVTaLtquiyJ2CAK/qFIX/ZFf7xhDaBZHd2RrztxvHjVmmrhoXaJ79w5MeOB2A5bTPMDcFhzHRTgaIY6ikjAMkecZfv74jq9fZoii8ECNMYZmo4G311doNhsQFodh1HF2ZuwwXsO2BeI0gyw+IKGqUfkYHz99xv3DN8RxQjJaLI5RM6lD3/cRBAF6vVuih263W3GDTqcD13EQJRnSbIJUjUtBnEhaJEeiJjR+KWy3keUFpKKVsxxKV6VQFPRNSnieS0JVTtAyWdyT/D3FD5HIjITpsZDBb50jTwKoaEAEJElK0XA4xGAwgOdqoaSoshQkqaqqrIRHHXLTgNu6RTt5hB/PiV+4vgloTy/pMBxwzmELgYjiyfGUBAVFVSU6rpw8/C+0zFPU22O8Kv7iJP+Dk+w36l4XpnFKMguWZVFkDwnF0lsipUJakeV5WfeyXYc0weIMgtUhuFFiWQJC2GDMRL/fx3Q6xXK5xNN6jdVqhc3mCdvtFvP5HJl6Fupa0zLmXIB5V+Ud1DDvDbjrg9F2HAvXJNxsNlgsFpjNZqVE38m9bBeZhKXIOQcXLrhFnemxvuD07zny7qA0erI+sOPODpF3wiZ0dP0qmNumsaiEnGLTodg2RvRSouqV7Ce/lGn+AcEOYKn+FnaEAAAAAElFTkSuQmCC')",backgroundSize:"cover",display:"block"}})),"\n  ",Object(n.b)("img",l({parentName:"span"},{className:"gatsby-resp-image-image",alt:"Grid Example",title:"Grid Example",src:"/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png",srcSet:["/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/7fc1e/Article_05.png 288w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/a5df1/Article_05.png 576w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png 1152w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/362ee/Article_05.png 1600w"],sizes:"(max-width: 1152px) 100vw, 1152px",style:{width:"100%",height:"100%",margin:"0",verticalAlign:"middle",position:"absolute",top:"0",left:"0"},loading:"lazy"})),"\n    ")),Object(n.b)(s,{colMd:4,colLg:4,noGutterMdLeft:!0,mdxType:"Column"},Object(n.b)("span",{className:"gatsby-resp-image-wrapper",style:{position:"relative",display:"block",marginLeft:"auto",marginRight:"auto",maxWidth:"1152px"}},"\n      ",Object(n.b)("span",l({parentName:"span"},{className:"gatsby-resp-image-background-image",style:{paddingBottom:"56.25%",position:"relative",bottom:"0",left:"0",backgroundImage:"url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAALCAYAAAB/Ca1DAAAACXBIWXMAAAsSAAALEgHS3X78AAACB0lEQVQoz12TS2/aQBRGWTTbqDie8fghSIRpkiJCgrBE8WvGNlRNaVTaLtquiyJ2CAK/qFIX/ZFf7xhDaBZHd2RrztxvHjVmmrhoXaJ79w5MeOB2A5bTPMDcFhzHRTgaIY6ikjAMkecZfv74jq9fZoii8ECNMYZmo4G311doNhsQFodh1HF2ZuwwXsO2BeI0gyw+IKGqUfkYHz99xv3DN8RxQjJaLI5RM6lD3/cRBAF6vVuih263W3GDTqcD13EQJRnSbIJUjUtBnEhaJEeiJjR+KWy3keUFpKKVsxxKV6VQFPRNSnieS0JVTtAyWdyT/D3FD5HIjITpsZDBb50jTwKoaEAEJElK0XA4xGAwgOdqoaSoshQkqaqqrIRHHXLTgNu6RTt5hB/PiV+4vgloTy/pMBxwzmELgYjiyfGUBAVFVSU6rpw8/C+0zFPU22O8Kv7iJP+Dk+w36l4XpnFKMguWZVFkDwnF0lsipUJakeV5WfeyXYc0weIMgtUhuFFiWQJC2GDMRL/fx3Q6xXK5xNN6jdVqhc3mCdvtFvP5HJl6Fupa0zLmXIB5V+Ud1DDvDbjrg9F2HAvXJNxsNlgsFpjNZqVE38m9bBeZhKXIOQcXLrhFnemxvuD07zny7qA0erI+sOPODpF3wiZ0dP0qmNumsaiEnGLTodg2RvRSouqV7Ce/lGn+AcEOYKn+FnaEAAAAAElFTkSuQmCC')",backgroundSize:"cover",display:"block"}})),"\n  ",Object(n.b)("img",l({parentName:"span"},{className:"gatsby-resp-image-image",alt:"Grid Example",title:"Grid Example",src:"/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png",srcSet:["/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/7fc1e/Article_05.png 288w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/a5df1/Article_05.png 576w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png 1152w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/362ee/Article_05.png 1600w"],sizes:"(max-width: 1152px) 100vw, 1152px",style:{width:"100%",height:"100%",margin:"0",verticalAlign:"middle",position:"absolute",top:"0",left:"0"},loading:"lazy"})),"\n    ")),Object(n.b)(s,{colMd:4,colLg:4,noGutterMdLeft:!0,mdxType:"Column"},Object(n.b)("span",{className:"gatsby-resp-image-wrapper",style:{position:"relative",display:"block",marginLeft:"auto",marginRight:"auto",maxWidth:"1152px"}},"\n      ",Object(n.b)("span",l({parentName:"span"},{className:"gatsby-resp-image-background-image",style:{paddingBottom:"56.25%",position:"relative",bottom:"0",left:"0",backgroundImage:"url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAALCAYAAAB/Ca1DAAAACXBIWXMAAAsSAAALEgHS3X78AAACB0lEQVQoz12TS2/aQBRGWTTbqDie8fghSIRpkiJCgrBE8WvGNlRNaVTaLtquiyJ2CAK/qFIX/ZFf7xhDaBZHd2RrztxvHjVmmrhoXaJ79w5MeOB2A5bTPMDcFhzHRTgaIY6ikjAMkecZfv74jq9fZoii8ECNMYZmo4G311doNhsQFodh1HF2ZuwwXsO2BeI0gyw+IKGqUfkYHz99xv3DN8RxQjJaLI5RM6lD3/cRBAF6vVuih263W3GDTqcD13EQJRnSbIJUjUtBnEhaJEeiJjR+KWy3keUFpKKVsxxKV6VQFPRNSnieS0JVTtAyWdyT/D3FD5HIjITpsZDBb50jTwKoaEAEJElK0XA4xGAwgOdqoaSoshQkqaqqrIRHHXLTgNu6RTt5hB/PiV+4vgloTy/pMBxwzmELgYjiyfGUBAVFVSU6rpw8/C+0zFPU22O8Kv7iJP+Dk+w36l4XpnFKMguWZVFkDwnF0lsipUJakeV5WfeyXYc0weIMgtUhuFFiWQJC2GDMRL/fx3Q6xXK5xNN6jdVqhc3mCdvtFvP5HJl6Fupa0zLmXIB5V+Ud1DDvDbjrg9F2HAvXJNxsNlgsFpjNZqVE38m9bBeZhKXIOQcXLrhFnemxvuD07zny7qA0erI+sOPODpF3wiZ0dP0qmNumsaiEnGLTodg2RvRSouqV7Ce/lGn+AcEOYKn+FnaEAAAAAElFTkSuQmCC')",backgroundSize:"cover",display:"block"}})),"\n  ",Object(n.b)("img",l({parentName:"span"},{className:"gatsby-resp-image-image",alt:"Grid Example",title:"Grid Example",src:"/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png",srcSet:["/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/7fc1e/Article_05.png 288w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/a5df1/Article_05.png 576w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png 1152w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/362ee/Article_05.png 1600w"],sizes:"(max-width: 1152px) 100vw, 1152px",style:{width:"100%",height:"100%",margin:"0",verticalAlign:"middle",position:"absolute",top:"0",left:"0"},loading:"lazy"})),"\n    "))),Object(n.b)(m,{mdxType:"Title"},"No gutter"),Object(n.b)(p,{mdxType:"Row"},Object(n.b)(s,{colMd:4,colLg:4,noGutterSm:!0,mdxType:"Column"},Object(n.b)("span",{className:"gatsby-resp-image-wrapper",style:{position:"relative",display:"block",marginLeft:"auto",marginRight:"auto",maxWidth:"1152px"}},"\n      ",Object(n.b)("span",l({parentName:"span"},{className:"gatsby-resp-image-background-image",style:{paddingBottom:"56.25%",position:"relative",bottom:"0",left:"0",backgroundImage:"url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAALCAYAAAB/Ca1DAAAACXBIWXMAAAsSAAALEgHS3X78AAACB0lEQVQoz12TS2/aQBRGWTTbqDie8fghSIRpkiJCgrBE8WvGNlRNaVTaLtquiyJ2CAK/qFIX/ZFf7xhDaBZHd2RrztxvHjVmmrhoXaJ79w5MeOB2A5bTPMDcFhzHRTgaIY6ikjAMkecZfv74jq9fZoii8ECNMYZmo4G311doNhsQFodh1HF2ZuwwXsO2BeI0gyw+IKGqUfkYHz99xv3DN8RxQjJaLI5RM6lD3/cRBAF6vVuih263W3GDTqcD13EQJRnSbIJUjUtBnEhaJEeiJjR+KWy3keUFpKKVsxxKV6VQFPRNSnieS0JVTtAyWdyT/D3FD5HIjITpsZDBb50jTwKoaEAEJElK0XA4xGAwgOdqoaSoshQkqaqqrIRHHXLTgNu6RTt5hB/PiV+4vgloTy/pMBxwzmELgYjiyfGUBAVFVSU6rpw8/C+0zFPU22O8Kv7iJP+Dk+w36l4XpnFKMguWZVFkDwnF0lsipUJakeV5WfeyXYc0weIMgtUhuFFiWQJC2GDMRL/fx3Q6xXK5xNN6jdVqhc3mCdvtFvP5HJl6Fupa0zLmXIB5V+Ud1DDvDbjrg9F2HAvXJNxsNlgsFpjNZqVE38m9bBeZhKXIOQcXLrhFnemxvuD07zny7qA0erI+sOPODpF3wiZ0dP0qmNumsaiEnGLTodg2RvRSouqV7Ce/lGn+AcEOYKn+FnaEAAAAAElFTkSuQmCC')",backgroundSize:"cover",display:"block"}})),"\n  ",Object(n.b)("img",l({parentName:"span"},{className:"gatsby-resp-image-image",alt:"Grid Example",title:"Grid Example",src:"/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png",srcSet:["/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/7fc1e/Article_05.png 288w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/a5df1/Article_05.png 576w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png 1152w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/362ee/Article_05.png 1600w"],sizes:"(max-width: 1152px) 100vw, 1152px",style:{width:"100%",height:"100%",margin:"0",verticalAlign:"middle",position:"absolute",top:"0",left:"0"},loading:"lazy"})),"\n    ")),Object(n.b)(s,{colMd:4,colLg:4,noGutterSm:!0,mdxType:"Column"},Object(n.b)("span",{className:"gatsby-resp-image-wrapper",style:{position:"relative",display:"block",marginLeft:"auto",marginRight:"auto",maxWidth:"1152px"}},"\n      ",Object(n.b)("span",l({parentName:"span"},{className:"gatsby-resp-image-background-image",style:{paddingBottom:"56.25%",position:"relative",bottom:"0",left:"0",backgroundImage:"url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAALCAYAAAB/Ca1DAAAACXBIWXMAAAsSAAALEgHS3X78AAACB0lEQVQoz12TS2/aQBRGWTTbqDie8fghSIRpkiJCgrBE8WvGNlRNaVTaLtquiyJ2CAK/qFIX/ZFf7xhDaBZHd2RrztxvHjVmmrhoXaJ79w5MeOB2A5bTPMDcFhzHRTgaIY6ikjAMkecZfv74jq9fZoii8ECNMYZmo4G311doNhsQFodh1HF2ZuwwXsO2BeI0gyw+IKGqUfkYHz99xv3DN8RxQjJaLI5RM6lD3/cRBAF6vVuih263W3GDTqcD13EQJRnSbIJUjUtBnEhaJEeiJjR+KWy3keUFpKKVsxxKV6VQFPRNSnieS0JVTtAyWdyT/D3FD5HIjITpsZDBb50jTwKoaEAEJElK0XA4xGAwgOdqoaSoshQkqaqqrIRHHXLTgNu6RTt5hB/PiV+4vgloTy/pMBxwzmELgYjiyfGUBAVFVSU6rpw8/C+0zFPU22O8Kv7iJP+Dk+w36l4XpnFKMguWZVFkDwnF0lsipUJakeV5WfeyXYc0weIMgtUhuFFiWQJC2GDMRL/fx3Q6xXK5xNN6jdVqhc3mCdvtFvP5HJl6Fupa0zLmXIB5V+Ud1DDvDbjrg9F2HAvXJNxsNlgsFpjNZqVE38m9bBeZhKXIOQcXLrhFnemxvuD07zny7qA0erI+sOPODpF3wiZ0dP0qmNumsaiEnGLTodg2RvRSouqV7Ce/lGn+AcEOYKn+FnaEAAAAAElFTkSuQmCC')",backgroundSize:"cover",display:"block"}})),"\n  ",Object(n.b)("img",l({parentName:"span"},{className:"gatsby-resp-image-image",alt:"Grid Example",title:"Grid Example",src:"/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png",srcSet:["/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/7fc1e/Article_05.png 288w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/a5df1/Article_05.png 576w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png 1152w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/362ee/Article_05.png 1600w"],sizes:"(max-width: 1152px) 100vw, 1152px",style:{width:"100%",height:"100%",margin:"0",verticalAlign:"middle",position:"absolute",top:"0",left:"0"},loading:"lazy"})),"\n    ")),Object(n.b)(s,{colMd:4,colLg:4,noGutterSm:!0,mdxType:"Column"},Object(n.b)("span",{className:"gatsby-resp-image-wrapper",style:{position:"relative",display:"block",marginLeft:"auto",marginRight:"auto",maxWidth:"1152px"}},"\n      ",Object(n.b)("span",l({parentName:"span"},{className:"gatsby-resp-image-background-image",style:{paddingBottom:"56.25%",position:"relative",bottom:"0",left:"0",backgroundImage:"url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAALCAYAAAB/Ca1DAAAACXBIWXMAAAsSAAALEgHS3X78AAACB0lEQVQoz12TS2/aQBRGWTTbqDie8fghSIRpkiJCgrBE8WvGNlRNaVTaLtquiyJ2CAK/qFIX/ZFf7xhDaBZHd2RrztxvHjVmmrhoXaJ79w5MeOB2A5bTPMDcFhzHRTgaIY6ikjAMkecZfv74jq9fZoii8ECNMYZmo4G311doNhsQFodh1HF2ZuwwXsO2BeI0gyw+IKGqUfkYHz99xv3DN8RxQjJaLI5RM6lD3/cRBAF6vVuih263W3GDTqcD13EQJRnSbIJUjUtBnEhaJEeiJjR+KWy3keUFpKKVsxxKV6VQFPRNSnieS0JVTtAyWdyT/D3FD5HIjITpsZDBb50jTwKoaEAEJElK0XA4xGAwgOdqoaSoshQkqaqqrIRHHXLTgNu6RTt5hB/PiV+4vgloTy/pMBxwzmELgYjiyfGUBAVFVSU6rpw8/C+0zFPU22O8Kv7iJP+Dk+w36l4XpnFKMguWZVFkDwnF0lsipUJakeV5WfeyXYc0weIMgtUhuFFiWQJC2GDMRL/fx3Q6xXK5xNN6jdVqhc3mCdvtFvP5HJl6Fupa0zLmXIB5V+Ud1DDvDbjrg9F2HAvXJNxsNlgsFpjNZqVE38m9bBeZhKXIOQcXLrhFnemxvuD07zny7qA0erI+sOPODpF3wiZ0dP0qmNumsaiEnGLTodg2RvRSouqV7Ce/lGn+AcEOYKn+FnaEAAAAAElFTkSuQmCC')",backgroundSize:"cover",display:"block"}})),"\n  ",Object(n.b)("img",l({parentName:"span"},{className:"gatsby-resp-image-image",alt:"Grid Example",title:"Grid Example",src:"/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png",srcSet:["/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/7fc1e/Article_05.png 288w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/a5df1/Article_05.png 576w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png 1152w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/362ee/Article_05.png 1600w"],sizes:"(max-width: 1152px) 100vw, 1152px",style:{width:"100%",height:"100%",margin:"0",verticalAlign:"middle",position:"absolute",top:"0",left:"0"},loading:"lazy"})),"\n    "))),Object(n.b)(m,{mdxType:"Title"},"Offset"),Object(n.b)(p,{mdxType:"Row"},Object(n.b)(s,{colMd:4,colLg:4,offsetLg:4,mdxType:"Column"},Object(n.b)("span",{className:"gatsby-resp-image-wrapper",style:{position:"relative",display:"block",marginLeft:"auto",marginRight:"auto",maxWidth:"1152px"}},"\n      ",Object(n.b)("span",l({parentName:"span"},{className:"gatsby-resp-image-background-image",style:{paddingBottom:"56.25%",position:"relative",bottom:"0",left:"0",backgroundImage:"url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAALCAYAAAB/Ca1DAAAACXBIWXMAAAsSAAALEgHS3X78AAACB0lEQVQoz12TS2/aQBRGWTTbqDie8fghSIRpkiJCgrBE8WvGNlRNaVTaLtquiyJ2CAK/qFIX/ZFf7xhDaBZHd2RrztxvHjVmmrhoXaJ79w5MeOB2A5bTPMDcFhzHRTgaIY6ikjAMkecZfv74jq9fZoii8ECNMYZmo4G311doNhsQFodh1HF2ZuwwXsO2BeI0gyw+IKGqUfkYHz99xv3DN8RxQjJaLI5RM6lD3/cRBAF6vVuih263W3GDTqcD13EQJRnSbIJUjUtBnEhaJEeiJjR+KWy3keUFpKKVsxxKV6VQFPRNSnieS0JVTtAyWdyT/D3FD5HIjITpsZDBb50jTwKoaEAEJElK0XA4xGAwgOdqoaSoshQkqaqqrIRHHXLTgNu6RTt5hB/PiV+4vgloTy/pMBxwzmELgYjiyfGUBAVFVSU6rpw8/C+0zFPU22O8Kv7iJP+Dk+w36l4XpnFKMguWZVFkDwnF0lsipUJakeV5WfeyXYc0weIMgtUhuFFiWQJC2GDMRL/fx3Q6xXK5xNN6jdVqhc3mCdvtFvP5HJl6Fupa0zLmXIB5V+Ud1DDvDbjrg9F2HAvXJNxsNlgsFpjNZqVE38m9bBeZhKXIOQcXLrhFnemxvuD07zny7qA0erI+sOPODpF3wiZ0dP0qmNumsaiEnGLTodg2RvRSouqV7Ce/lGn+AcEOYKn+FnaEAAAAAElFTkSuQmCC')",backgroundSize:"cover",display:"block"}})),"\n  ",Object(n.b)("img",l({parentName:"span"},{className:"gatsby-resp-image-image",alt:"Grid Example",title:"Grid Example",src:"/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png",srcSet:["/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/7fc1e/Article_05.png 288w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/a5df1/Article_05.png 576w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png 1152w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/362ee/Article_05.png 1600w"],sizes:"(max-width: 1152px) 100vw, 1152px",style:{width:"100%",height:"100%",margin:"0",verticalAlign:"middle",position:"absolute",top:"0",left:"0"},loading:"lazy"})),"\n    ")),Object(n.b)(s,{colMd:4,colLg:4,mdxType:"Column"},Object(n.b)("span",{className:"gatsby-resp-image-wrapper",style:{position:"relative",display:"block",marginLeft:"auto",marginRight:"auto",maxWidth:"1152px"}},"\n      ",Object(n.b)("span",l({parentName:"span"},{className:"gatsby-resp-image-background-image",style:{paddingBottom:"56.25%",position:"relative",bottom:"0",left:"0",backgroundImage:"url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAALCAYAAAB/Ca1DAAAACXBIWXMAAAsSAAALEgHS3X78AAACB0lEQVQoz12TS2/aQBRGWTTbqDie8fghSIRpkiJCgrBE8WvGNlRNaVTaLtquiyJ2CAK/qFIX/ZFf7xhDaBZHd2RrztxvHjVmmrhoXaJ79w5MeOB2A5bTPMDcFhzHRTgaIY6ikjAMkecZfv74jq9fZoii8ECNMYZmo4G311doNhsQFodh1HF2ZuwwXsO2BeI0gyw+IKGqUfkYHz99xv3DN8RxQjJaLI5RM6lD3/cRBAF6vVuih263W3GDTqcD13EQJRnSbIJUjUtBnEhaJEeiJjR+KWy3keUFpKKVsxxKV6VQFPRNSnieS0JVTtAyWdyT/D3FD5HIjITpsZDBb50jTwKoaEAEJElK0XA4xGAwgOdqoaSoshQkqaqqrIRHHXLTgNu6RTt5hB/PiV+4vgloTy/pMBxwzmELgYjiyfGUBAVFVSU6rpw8/C+0zFPU22O8Kv7iJP+Dk+w36l4XpnFKMguWZVFkDwnF0lsipUJakeV5WfeyXYc0weIMgtUhuFFiWQJC2GDMRL/fx3Q6xXK5xNN6jdVqhc3mCdvtFvP5HJl6Fupa0zLmXIB5V+Ud1DDvDbjrg9F2HAvXJNxsNlgsFpjNZqVE38m9bBeZhKXIOQcXLrhFnemxvuD07zny7qA0erI+sOPODpF3wiZ0dP0qmNumsaiEnGLTodg2RvRSouqV7Ce/lGn+AcEOYKn+FnaEAAAAAElFTkSuQmCC')",backgroundSize:"cover",display:"block"}})),"\n  ",Object(n.b)("img",l({parentName:"span"},{className:"gatsby-resp-image-image",alt:"Grid Example",title:"Grid Example",src:"/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png",srcSet:["/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/7fc1e/Article_05.png 288w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/a5df1/Article_05.png 576w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/3cbba/Article_05.png 1152w","/mcas/static/dc51d23a5322c2511205c8c525bbe8ee/362ee/Article_05.png 1600w"],sizes:"(max-width: 1152px) 100vw, 1152px",style:{width:"100%",height:"100%",margin:"0",verticalAlign:"middle",position:"absolute",top:"0",left:"0"},loading:"lazy"})),"\n    "))),Object(n.b)("h3",null,"Code"),Object(n.b)("pre",null,Object(n.b)("code",l({parentName:"pre"},{className:"language-jsx",metastring:"path=components/Grid.js src=https://github.com/carbon-design-system/gatsby-theme-carbon/tree/master/packages/gatsby-theme-carbon/src/components/Grid",path:"components/Grid.js",src:"https://github.com/carbon-design-system/gatsby-theme-carbon/tree/master/packages/gatsby-theme-carbon/src/components/Grid"}),"<Row>\n  <Column colMd={4} colLg={4}>\n    ![Grid Example](images/Article_05.png)\n  </Column>\n  <Column colMd={4} colLg={4}>\n    ![Grid Example](images/Article_05.png)\n  </Column>\n  <Column colMd={4} colLg={4}>\n    ![Grid Example](images/Article_05.png)\n  </Column>\n</Row>\n")),Object(n.b)(m,{mdxType:"Title"},"No gutter left"),Object(n.b)("pre",null,Object(n.b)("code",l({parentName:"pre"},{className:"language-jsx",metastring:"path=components/Grid.js src=https://github.com/carbon-design-system/gatsby-theme-carbon/tree/master/packages/gatsby-theme-carbon/src/components/Grid",path:"components/Grid.js",src:"https://github.com/carbon-design-system/gatsby-theme-carbon/tree/master/packages/gatsby-theme-carbon/src/components/Grid"}),"<Row>\n  <Column colMd={4} colLg={4} noGutterMdLeft>\n    ![Grid Example](images/Article_05.png)\n  </Column>\n  <Column colMd={4} colLg={4} noGutterMdLeft>\n    ![Grid Example](images/Article_05.png)\n  </Column>\n  <Column colMd={4} colLg={4} noGutterMdLeft>\n    ![Grid Example](images/Article_05.png)\n  </Column>\n</Row>\n")),Object(n.b)(m,{mdxType:"Title"},"No gutter"),Object(n.b)("pre",null,Object(n.b)("code",l({parentName:"pre"},{className:"language-jsx",metastring:"path=components/Grid.js src=https://github.com/carbon-design-system/gatsby-theme-carbon/tree/master/packages/gatsby-theme-carbon/src/components/Grid",path:"components/Grid.js",src:"https://github.com/carbon-design-system/gatsby-theme-carbon/tree/master/packages/gatsby-theme-carbon/src/components/Grid"}),"<Row>\n  <Column colMd={4} colLg={4} noGutterSm>\n    ![Grid Example](images/Article_05.png)\n  </Column>\n  <Column colMd={4} colLg={4} noGutterSm>\n    ![Grid Example](images/Article_05.png)\n  </Column>\n  <Column colMd={4} colLg={4} noGutterSm>\n    ![Grid Example](images/Article_05.png)\n  </Column>\n</Row>\n")),Object(n.b)(m,{mdxType:"Title"},"Offset"),Object(n.b)("pre",null,Object(n.b)("code",l({parentName:"pre"},{className:"language-jsx",metastring:"path=components/Grid.js src=https://github.com/carbon-design-system/gatsby-theme-carbon/tree/master/packages/gatsby-theme-carbon/src/components/Grid",path:"components/Grid.js",src:"https://github.com/carbon-design-system/gatsby-theme-carbon/tree/master/packages/gatsby-theme-carbon/src/components/Grid"}),"<Row>\n  <Column colMd={4} colLg={4} offsetLg={4}>\n    ![Grid Example](images/Article_05.png)\n  </Column>\n  <Column colMd={4} colLg={4}>\n    ![Grid Example](images/Article_05.png)\n  </Column>\n</Row>\n")),Object(n.b)(m,{mdxType:"Title"},"Column props"),Object(n.b)("table",null,Object(n.b)("thead",{parentName:"table"},Object(n.b)("tr",{parentName:"thead"},Object(n.b)("th",l({parentName:"tr"},{align:null}),"property"),Object(n.b)("th",l({parentName:"tr"},{align:null}),"propType"),Object(n.b)("th",l({parentName:"tr"},{align:null}),"required"),Object(n.b)("th",l({parentName:"tr"},{align:null}),"default"),Object(n.b)("th",l({parentName:"tr"},{align:null}),"description"))),Object(n.b)("tbody",{parentName:"table"},Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"children"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"node"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}))),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"className"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"string"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Add custom class name")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"colSm"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"number"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify the col width at small breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"colMd"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"number"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify the col width at medium breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"colLg"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"number"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"12"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify the col width at large breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"colXl"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"number"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify the col width at x-large breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"colMax"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"number"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify the col width at max breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"offsetSm"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"number"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify the col offset at small breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"offsetMd"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"number"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify the col offset at medium breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"offsetLg"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"number"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify the col offset at large breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"offsetXl"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"number"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify the col offset at x-large breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"offsetMax"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"number"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify the col offset at max breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"noGutterSm"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"bool"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify no-gutter at small breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"noGutterMd"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"bool"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify no-gutter at medium breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"noGutterLg"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"bool"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify no-gutter at large breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"noGutterXl"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"bool"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify no-gutter at x-large breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"noGutterMax"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"bool"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify no-gutter at max breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"noGutterSmLeft"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"bool"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify no-gutter left at small breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"noGutterMdLeft"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"bool"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify no-gutter left at medium breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"noGutterLgLeft"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"bool"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify no-gutter left at large breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"noGutterXlLeft"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"bool"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify no-gutter left at x-large breakpoint")),Object(n.b)("tr",{parentName:"tbody"},Object(n.b)("td",l({parentName:"tr"},{align:null}),"noGutterMaxLeft"),Object(n.b)("td",l({parentName:"tr"},{align:null}),"bool"),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null})),Object(n.b)("td",l({parentName:"tr"},{align:null}),"Specify no-gutter left at max breakpoint")))))}d.isMDXComponent=!0}}]);
//# sourceMappingURL=component---src-pages-components-grid-mdx-d5e5f704ab4069e260e1.js.map