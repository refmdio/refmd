import { createContext, useContext, type Accessor } from "solid-js";

type FormControlProps = {
  id?: string;
  "aria-describedby"?: string;
  "aria-invalid"?: boolean;
};

const FormControlContext = createContext<Accessor<FormControlProps>>();

function useOptionalFormControlProps() {
  return useContext(FormControlContext);
}

export { FormControlContext, useOptionalFormControlProps };
export type { FormControlProps };
