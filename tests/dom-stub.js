/* =========================================================================
   Phishing Email Analyser - tests/dom-stub.js
   -------------------------------------------------------------------------
   A very small stand-in for the browser's document object.

   Why this exists: the interface code (js/app.js) has to be checked for
   mistakes, but the analysis engine and the tests must be able to run in
   plain Node.js without installing a browser automation library. This stub
   implements only the handful of things app.js uses, which is enough to
   render a full report and inspect the result.

   It deliberately models the important security property of the real DOM:
   textContent stores text and cannot create elements, whereas innerHTML is
   recorded separately. The checks in tests/run-ui-tests.js then prove that
   nothing a visitor pasted ever ends up as markup.
   ========================================================================= */

'use strict';

function createStubDocument() {
  const registry = {};

  function makeNode(tagName) {
    const node = {
      nodeType: 1,
      tagName: String(tagName || 'div').toUpperCase(),
      childNodes: [],
      attributes: {},
      style: {},
      className: '',
      _text: '',
      _html: '',

      get firstChild() {
        return this.childNodes.length ? this.childNodes[0] : null;
      },

      get textContent() {
        let out = this._text;
        this.childNodes.forEach(function (child) {
          out += child.textContent;
        });
        return out;
      },

      set textContent(value) {
        this._text = String(value);
        this.childNodes = [];
      },

      get innerHTML() {
        return this._html;
      },

      set innerHTML(value) {
        this._html = String(value);
      },

      appendChild(child) {
        this.childNodes.push(child);
        return child;
      },

      removeChild(child) {
        const index = this.childNodes.indexOf(child);
        if (index !== -1) this.childNodes.splice(index, 1);
        return child;
      },

      setAttribute(name, value) {
        this.attributes[name] = String(value);
      },

      getAttribute(name) {
        return Object.prototype.hasOwnProperty.call(this.attributes, name) ? this.attributes[name] : null;
      },

      hasAttribute(name) {
        return Object.prototype.hasOwnProperty.call(this.attributes, name);
      },

      removeAttribute(name) {
        delete this.attributes[name];
      },

      addEventListener() {},
      removeEventListener() {},
      focus() {},
      select() {},
      click() {},
      scrollIntoView() {}
    };
    return node;
  }

  const document = {
    readyState: 'loading',
    documentElement: makeNode('html'),
    body: makeNode('body'),
    execCommand: function () { return false; },

    createElement: makeNode,

    createElementNS: function (namespace, tagName) {
      return makeNode(tagName);
    },

    createTextNode: function (text) {
      return { nodeType: 3, childNodes: [], textContent: String(text) };
    },

    createDocumentFragment: function () {
      const fragment = makeNode('#fragment');
      fragment.nodeType = 11;
      return fragment;
    },

    getElementById: function (id) {
      return Object.prototype.hasOwnProperty.call(registry, id) ? registry[id] : null;
    },

    addEventListener: function () {},

    /* Not part of the real DOM: lets a test register a node under an id. */
    __register: function (id, node) {
      registry[id] = node;
      return node;
    }
  };

  return document;
}

module.exports = { createStubDocument: createStubDocument };
