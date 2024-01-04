import * as fs from 'fs';
import * as eslint from 'eslint';


let replayText = fs.readFileSync('replay.cc', 'utf8');

let regex = new RegExp('//js', 'g');
let endRegex = new RegExp('\\)""""', 'g');
const linter = new eslint.Linter();

function findMatches(text: string, regex: RegExp) {
    let match;
    const matches: number[] = [];
    while ((match = regex.exec(text)) != null) {
        const res = text.substr(0, match.index).split('\n').length;
        matches.push(res);
    }

    return matches
}

function getTextBlock(text: string, start: number, end: number) {
    return "//js\n" + text.split('\n').slice(start, end - 1).join('\n');
}

function lintScript(text: string) {
    const messages = linter.verify(text, {
        parserOptions: {
            ecmaVersion: 2023,
            sourceType: "module",
        },
        rules: {
            "no-undef": ["error"]
        },
        // env: {
        //     "browser": true
        // },
        globals: {
            __RECORD_REPLAY_ARGUMENTS__: true,
            __RECORD_REPLAY__: true,
            log: true,

            // browser globals
            CSSStyleValue: true,
            CSSStyleDeclaration: true,
            Element: true,
            Map: true,
            Node: true,
            window: true,
            URL: true,
            Set: true,
            location: true,

            // CDP
            InspectorUtils: true

        }
    });

    if (messages.length > 0) {
        console.log(messages)
    }

    return messages.length > 0
}

const lineNumbers = findMatches(replayText, regex)
const endLineNumbers = findMatches(replayText, endRegex)
// console.log('Lines with "//js":', lineNumbers);
// console.log('Lines with ")"""":', endLineNumbers);

const textBlocks = lineNumbers.map((lineNumber, index) => getTextBlock(replayText, lineNumber, endLineNumbers[index]))

const hasErrors = textBlocks.some(block => lintScript(block))

if (hasErrors) {
    console.log('ESLint issue')
    process.exit(1)
}

