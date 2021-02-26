/*
 * Copyright (c) 2020 AdScore Technologies DMCC [AE]
 *
 * Licensed under MIT License;
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.adscore.signature;

import java.util.HashMap;

/**
 * This class is a wrapper for a result of unpack() method. Contains data end error message in
 * separate variables
 *
 * <p>Copyright (c) 2020 AdScore Technologies DMCC [AE]
 *
 * @author lhyla
 */
class UnpackResult {

  private HashMap<String, Object> data;
  private String error;

  UnpackResult(HashMap<String, Object> data) {
    this.data = data;
  }

  UnpackResult(String error) {
    this.error = error;
  }

  HashMap<String, Object> getData() {
    return data;
  }

  String getError() {
    return error;
  }
}
