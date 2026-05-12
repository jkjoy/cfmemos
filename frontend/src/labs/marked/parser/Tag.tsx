import { matcher } from "../matcher";

export const TAG_REG = /(^|[\s([{"'“‘（【《「『<,.;:!?，。！？；：、])#([^\s#,]+)/;

const renderer = (rawStr: string) => {
  const matchResult = matcher(rawStr, TAG_REG);
  if (!matchResult) {
    return rawStr;
  }

  return (
    <>
      {matchResult[1]}
      <span className="tag-span">#{matchResult[2]}</span>
    </>
  );
};

export default {
  name: "tag",
  regexp: TAG_REG,
  renderer,
};
