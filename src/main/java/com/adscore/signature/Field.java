package com.adscore.signature;

/**
 * Representation of fields present within signature
 *
 * @author Łukasz Hyła <lhyla@iterative.pl>
 * @copyright AdScore Technologies DMCC [AE]
 */
class Field {

  private String name;
  private String type;

  Field(String name, String type) {
    this.name = name;
    this.type = type;
  }

  String getName() {
    return name;
  }

  String getType() {
    return type;
  }
}
