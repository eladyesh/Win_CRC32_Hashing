rule crc32_hash
{
  meta:
    author = "elad_yesh"
    description = "crc32 constants"
  strings:
    $c = { 2083B8ED }
  condition:
    $c
}