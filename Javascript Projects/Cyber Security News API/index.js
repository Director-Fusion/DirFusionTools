// Listening Port
const PORT = 8088

// Intiazlize Packages
const express = require("express");
const axios = require("axios");
const cheerio = require("cheerio");
const { contains } = require("cheerio/lib/static");
const { getElementsByTagName } = require("domutils");
const app = express()


// Array for scrapper to push recv data into.
const articles = []

// Sources for the API to scrape.
const sources = [
    {
        name: 'ThreatPost',
        address: 'https://threatpost.com/',
        base: 'https://threatpost.com',
    },
    {
        name: 'NY Times',
        address: 'https://www.nytimes.com/search?query=cybersecurity',
        base: 'https://www.nytimes.com',
    },
    {
        name: 'CNN',
        address: 'https://www.cnn.com/search?q=CyberSecurity',
        base: 'https://www.cnn.com',
    },
    {
        name: 'Fox News',
        address: 'https://www.foxnews.com/search-results/search?q=cybersecurity',
        base: 'https://www.foxnews.com',
    },
    {
        name: 'The Guardian',
        address: 'https://www.theguardian.com/technology/data-computer-security',
        base: 'https://www.theguardian.com',
    }
]
/*
const keywords = [
    {
    keyword: "cyber",
    },
    {
    keyword: "cybersecurity",
    },
    {
    keyword: "hacker",
    },
    {
    keyword: "hack",
    },
    {
    keyword: "hacked",
    },
    {
    keyword: "cert",
    },
    {
    keyword: "ics",
    },
    {
    keyword: "scada",
    },
    {
    keyword: "ransomware",
    },
    {
    keyword: "ransom",
    },
];
*/

const keywords = [
    "cyber",
    //"cybersecurity",
    //"hacker",
    "hack",
    //"hacked",
    //"cert",
    //"ics",
    //"scada",
    //"ransomware",
    //"ransom",
    //"cyber attack",
];

function category() {
    keywords.forEach(keyword);
};

//taking input via news articles.

// Set root directory
app.get("/", function(req, res){
    console.log(__dirname);
    res.json("Welcome to my Cyber Security News API")
});

// News Scraper
app.get("/news", function(req, res){
    console.log(__dirname);
    res.json(articles)
});

// Scrape sources
/*
sources.forEach(source => {
    axios.get(source.address)
        .then(response => {
            const html = response.data
            const $ = cheerio.load(html)
                
            
            $('a').each((i, link) => {   
                keywords.forEach(i => {
            if (typeof link.attribs.href === 'udefined'){ return false }    
                const title = link.attribs.text;
                const url = link.attribs.href
                        //$$('a:contains(${i})', html).each(function () {
                        //const title = $(this).text()
                        //const url = $(this).attr('href')
                           
            articles.push({
                title,
                url: source.base + url,
                source: source.name,
            });   
        });
        });
    });
});
*/

// Scrape

sources.forEach(source => {
    axios.get(source.address)
        .then(response => {
            const html = response.data
            const $ = cheerio.load(html)

            //keywords.forEach(i => {
                //console.log(i+'a')
            
                $('a:contains()', html).each(function () {
                //$('a').each((i, link => {
                    //console.log(i+'b')
                    const title = $(this).text()
                    const url = $(this).attr('href')
                
            articles.push({
                title,
                
                url: source.base + url,
                source: source.name,
            });
            }));
        //});
        });
});

                
// Set socket listener for the API
app.listen(PORT, () => console.log(`server running on PORT ${PORT}`))