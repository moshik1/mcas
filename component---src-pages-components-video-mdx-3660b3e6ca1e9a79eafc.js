(window.webpackJsonp=window.webpackJsonp||[]).push([[38],{yylr:function(e,t,n){"use strict";n.r(t),n.d(t,"_frontmatter",(function(){return b})),n.d(t,"default",(function(){return s}));n("91GP"),n("rGqo"),n("yt8O"),n("Btvt"),n("RW0V"),n("q1tI");var a=n("7ljp"),r=n("013z");n("qKvR");function o(){return(o=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var a in n)Object.prototype.hasOwnProperty.call(n,a)&&(e[a]=n[a])}return e}).apply(this,arguments)}var b={},l=function(e){return function(t){return console.warn("Component "+e+" was not imported, exported, or provided by MDXProvider as global scope"),Object(a.b)("div",t)}},i=l("PageDescription"),c=l("Title"),d=l("Video"),p={_frontmatter:b},m=r.a;function s(e){var t=e.components,n=function(e,t){if(null==e)return{};var n,a,r={},o=Object.keys(e);for(a=0;a<o.length;a++)n=o[a],t.indexOf(n)>=0||(r[n]=e[n]);return r}(e,["components"]);return Object(a.b)(m,o({},p,n,{components:t,mdxType:"MDXLayout"}),Object(a.b)(i,{mdxType:"PageDescription"},Object(a.b)("p",null,"The ",Object(a.b)("inlineCode",{parentName:"p"},"<Video>")," component can render a Vimeo player or a html video player.")),Object(a.b)("h2",null,"Example"),Object(a.b)(c,{mdxType:"Title"},"Vimeo"),Object(a.b)(d,{title:"Carbon homepage video",vimeoId:"359578263",mdxType:"Video"}),Object(a.b)(c,{mdxType:"Title"},"Video"),Object(a.b)(d,{src:"/videos/hero-video.mp4",poster:"/images/poster.png",mdxType:"Video"},Object(a.b)("track",{kind:"captions",default:!0,src:"/videos/vtt/hero-video.vtt",srcLang:"en"})),Object(a.b)("h2",null,"Code"),Object(a.b)(c,{mdxType:"Title"},"Vimeo"),Object(a.b)("pre",null,Object(a.b)("code",o({parentName:"pre"},{className:"language-jsx",metastring:"path=components/Video/Video.js src=https://github.com/carbon-design-system/gatsby-theme-carbon/tree/master/packages/gatsby-theme-carbon/src/components/Video",path:"components/Video/Video.js",src:"https://github.com/carbon-design-system/gatsby-theme-carbon/tree/master/packages/gatsby-theme-carbon/src/components/Video"}),'<Video title="Carbon homepage video" vimeoId="322021187" />\n')),Object(a.b)(c,{mdxType:"Title"},"Video"),Object(a.b)("pre",null,Object(a.b)("code",o({parentName:"pre"},{className:"language-jsx",metastring:"path=components/Video/Video.js src=https://github.com/carbon-design-system/gatsby-theme-carbon/tree/master/packages/gatsby-theme-carbon/src/components/Video",path:"components/Video/Video.js",src:"https://github.com/carbon-design-system/gatsby-theme-carbon/tree/master/packages/gatsby-theme-carbon/src/components/Video"}),'<Video src="/videos/hero-video.mp4" poster="/images/poster.png">\n  <track kind="captions" default src="/videos/vtt/hero-video.vtt" srcLang="en" />\n</Video>\n')),Object(a.b)("h3",null,"Props"),Object(a.b)("table",null,Object(a.b)("thead",{parentName:"table"},Object(a.b)("tr",{parentName:"thead"},Object(a.b)("th",o({parentName:"tr"},{align:null}),"property"),Object(a.b)("th",o({parentName:"tr"},{align:null}),"propType"),Object(a.b)("th",o({parentName:"tr"},{align:null}),"required"),Object(a.b)("th",o({parentName:"tr"},{align:null}),"default"),Object(a.b)("th",o({parentName:"tr"},{align:null}),"description"))),Object(a.b)("tbody",{parentName:"table"},Object(a.b)("tr",{parentName:"tbody"},Object(a.b)("td",o({parentName:"tr"},{align:null}),"vimeoId"),Object(a.b)("td",o({parentName:"tr"},{align:null}),"string"),Object(a.b)("td",o({parentName:"tr"},{align:null})),Object(a.b)("td",o({parentName:"tr"},{align:null})),Object(a.b)("td",o({parentName:"tr"},{align:null}),"To find your ",Object(a.b)("inlineCode",{parentName:"td"},"vimeoId"),", go to the Vimeo page and find the video you want to put on your website. Once it is loaded, look at the URL and look for the numbers that come after the slash (/).")),Object(a.b)("tr",{parentName:"tbody"},Object(a.b)("td",o({parentName:"tr"},{align:null}),"src"),Object(a.b)("td",o({parentName:"tr"},{align:null}),"string"),Object(a.b)("td",o({parentName:"tr"},{align:null})),Object(a.b)("td",o({parentName:"tr"},{align:null})),Object(a.b)("td",o({parentName:"tr"},{align:null}),"Use the html ",Object(a.b)("inlineCode",{parentName:"td"},"<video>")," player with a local ",Object(a.b)("inlineCode",{parentName:"td"},".mp4")," video")),Object(a.b)("tr",{parentName:"tbody"},Object(a.b)("td",o({parentName:"tr"},{align:null}),"title"),Object(a.b)("td",o({parentName:"tr"},{align:null}),"string"),Object(a.b)("td",o({parentName:"tr"},{align:null})),Object(a.b)("td",o({parentName:"tr"},{align:null})),Object(a.b)("td",o({parentName:"tr"},{align:null}),"Vimeo title")),Object(a.b)("tr",{parentName:"tbody"},Object(a.b)("td",o({parentName:"tr"},{align:null}),"poster"),Object(a.b)("td",o({parentName:"tr"},{align:null}),"string"),Object(a.b)("td",o({parentName:"tr"},{align:null})),Object(a.b)("td",o({parentName:"tr"},{align:null})),Object(a.b)("td",o({parentName:"tr"},{align:null}),"Provides an image to show before the video loads, only works with ",Object(a.b)("inlineCode",{parentName:"td"},"src"))),Object(a.b)("tr",{parentName:"tbody"},Object(a.b)("td",o({parentName:"tr"},{align:null}),"children"),Object(a.b)("td",o({parentName:"tr"},{align:null}),Object(a.b)("a",o({parentName:"td"},{href:"https://developer.mozilla.org/en-US/docs/Web/HTML/Element/track"}),Object(a.b)("inlineCode",{parentName:"a"},"<track>"))),Object(a.b)("td",o({parentName:"tr"},{align:null})),Object(a.b)("td",o({parentName:"tr"},{align:null})),Object(a.b)("td",o({parentName:"tr"},{align:null}),Object(a.b)("em",{parentName:"td"},"non-vimeo only")," – Provide ",Object(a.b)("inlineCode",{parentName:"td"},".vtt")," file in your static directory to make your videos more accessible. Then add a track element with a src pointing to it Check out ",Object(a.b)("a",o({parentName:"td"},{href:"https://developer.mozilla.org/en-US/docs/Web/API/WebVTT_API#Tutorial_on_how_to_write_a_WebVTT_file"}),"this simple tutorial")," for getting started with writing vtt files.")),Object(a.b)("tr",{parentName:"tbody"},Object(a.b)("td",o({parentName:"tr"},{align:null}),"autoPlay"),Object(a.b)("td",o({parentName:"tr"},{align:null}),"boolean"),Object(a.b)("td",o({parentName:"tr"},{align:null})),Object(a.b)("td",o({parentName:"tr"},{align:null})),Object(a.b)("td",o({parentName:"tr"},{align:null}),"Whether or not the video should autoplay.")))))}s.isMDXComponent=!0}}]);
//# sourceMappingURL=component---src-pages-components-video-mdx-3660b3e6ca1e9a79eafc.js.map