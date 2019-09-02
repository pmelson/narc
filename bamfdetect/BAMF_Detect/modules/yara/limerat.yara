rule limerat {
  strings:
    $lr = "LimeRAT" wide
  condition:
    uint16be(0) == 0x4d5a and all of them
}
