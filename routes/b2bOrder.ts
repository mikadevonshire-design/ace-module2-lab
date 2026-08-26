/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''

      // Robust security validation on orderLinesData to prevent Sandbox Escape / RCE
      if (typeof orderLinesData !== 'string') {
        next(new Error('Invalid order lines data type'))
        return
      }

      if (orderLinesData.includes('\\')) {
        next(new Error('Potential code injection detected: backslashes are not allowed'))
        return
      }

      if (orderLinesData.includes('`')) {
        next(new Error('Potential code injection detected: backticks are not allowed'))
        return
      }

      // 1. Strip string literals first to prevent false positives on user text values
      let clean = orderLinesData.replace(/"[^"]*"|'[^']*'/g, '""')

      // 2. Strip comments to prevent comment-based bypasses
      clean = clean.replace(/\/\*[\s\S]*?\*\//g, '')
      clean = clean.replace(/\/\/.*/g, '')

      // 3. Block bracket member access (e.g. obj["constructor"] or obj[expr])
      const bracketMemberAccessPattern = /[a-zA-Z0-9_$"')\]]\s*\[/
      if (bracketMemberAccessPattern.test(clean)) {
        next(new Error('Potential code injection detected: dynamic property access is not allowed'))
        return
      }

      // 4. Block forbidden keywords
      const forbiddenKeywords = [
        'constructor',
        'prototype',
        '__proto__',
        'process',
        'require',
        'child_process',
        'Function',
        'eval',
        'exec',
        'spawn',
        'fork',
        'module',
        'Reflect',
        'Proxy',
        'Object',
        'Array',
        'this',
        'arguments',
        'caller',
        'callee',
        'window',
        'global',
        'document',
        'Buffer',
        'import',
        'Symbol',
        'Error',
        '__defineGetter__',
        '__defineSetter__',
        '__lookupGetter__',
        '__lookupSetter__'
      ]
      
      const forbiddenRegex = new RegExp(`\\b(${forbiddenKeywords.join('|')})\\b`, 'i')
      if (forbiddenRegex.test(clean)) {
        next(new Error('Potential code injection detected: forbidden keyword'))
        return
      }

      try {
        const sandbox = { safeEval, orderLinesData }
        vm.createContext(sandbox)
        vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
