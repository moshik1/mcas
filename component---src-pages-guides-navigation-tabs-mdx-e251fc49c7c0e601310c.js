(window.webpackJsonp=window.webpackJsonp||[]).push([[46],{ndPe:function(t,e,n){"use strict";n.r(e),n.d(e,"_frontmatter",(function(){return s})),n.d(e,"default",(function(){return l}));n("91GP"),n("rGqo"),n("yt8O"),n("Btvt"),n("RW0V"),n("q1tI");var o=n("7ljp"),a=n("013z");n("qKvR");function r(){return(r=Object.assign||function(t){for(var e=1;e<arguments.length;e++){var n=arguments[e];for(var o in n)Object.prototype.hasOwnProperty.call(n,o)&&(t[o]=n[o])}return t}).apply(this,arguments)}var i,s={},u=(i="PageDescription",function(t){return console.warn("Component "+i+" was not imported, exported, or provided by MDXProvider as global scope"),Object(o.b)("div",t)}),b={_frontmatter:s},c=a.a;function l(t){var e=t.components,n=function(t,e){if(null==t)return{};var n,o,a={},r=Object.keys(t);for(o=0;o<r.length;o++)n=r[o],e.indexOf(n)>=0||(a[n]=t[n]);return a}(t,["components"]);return Object(o.b)(c,r({},b,n,{components:e,mdxType:"MDXLayout"}),Object(o.b)(u,{mdxType:"PageDescription"},Object(o.b)("p",null,"You have the option of adding tabs to your pages. This is only recommended if you have several pages that will use the same tabs. If you only have one page with a set of tabs, it might be better for discoverability to change the tabs to menu items.")),Object(o.b)("h2",null,"Tabs in YAML"),Object(o.b)("p",null,"To create a tabbed page, you just need to point the theme to the path of your first tab. This is the structure of the YAML configuration for this page and it’s siblings."),Object(o.b)("pre",null,Object(o.b)("code",r({parentName:"pre"},{className:"language-yaml"}),"- title: Guides\n  pages:\n    - title: Configuration\n      path: /guides/configuration\n    - title: Shadowing\n      path: /guides/shadowing\n    - title: Styling\n      path: /guides/styling\n    - title: Navigation\n      path: /guides/navigation/sidebar\n")),Object(o.b)("h2",null,"File structure"),Object(o.b)("p",null,"Let’s check out the directory structure for this page. Notice how you’ll add another directory that corresponds with the one in the YAML file."),Object(o.b)("pre",null,Object(o.b)("code",r({parentName:"pre"},{}),".\n├── pages\n│   └── guides\n│       ├── configuration.mdx\n│       ├── shadowing.mdx\n│       ├── styling.mdx\n│       └── navigation\n│           ├── tabs.mdx\n│           └── sidebar.mdx\n")),Object(o.b)("h2",null,"Markdown updates"),Object(o.b)("p",null,"The last step is to add the name of your tabs to the front matter of each markdown file that has tabs."),Object(o.b)("p",null,Object(o.b)("strong",{parentName:"p"},"Known issue"),": at the moment, your tab name needs to match your title for the navigation components to function properly."),Object(o.b)("pre",null,Object(o.b)("code",r({parentName:"pre"},{className:"language-markdown"}),"---\ntitle: Sidebar\ntabs: ['Sidebar', 'Tabs']\n---\n")))}l.isMDXComponent=!0}}]);
//# sourceMappingURL=component---src-pages-guides-navigation-tabs-mdx-e251fc49c7c0e601310c.js.map