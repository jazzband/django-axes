import { createRoot } from "react-dom/client";
import "./styles.css";

const root = document.getElementById("root");
const page = root.dataset.page;
const errors = JSON.parse(document.getElementById("form-errors")?.textContent || "{}");
const csrfToken = document.querySelector("[name=csrfmiddlewaretoken]")?.value || "";

const errorMessages = (field) =>
  (errors[field] || []).map((error) => error.message).join(" ");

function Field({ id, label, type, autoComplete, error }) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        name={id}
        type={type}
        autoComplete={autoComplete}
        aria-invalid={Boolean(error)}
        aria-describedby={error ? `${id}-error` : undefined}
        required
      />
      {error && <p className="error" id={`${id}-error`} role="alert">{error}</p>}
    </div>
  );
}

function AuthPage() {
  const isRegistration = page === "register";
  const title = isRegistration ? "Rejestracja" : "Logowanie";
  const submitText = isRegistration ? "Utwórz konto" : "Zaloguj";
  const alternateText = isRegistration ? "Masz już konto?" : "Nie masz jeszcze konta?";
  const alternateLinkText = isRegistration ? "Zaloguj się" : "Utwórz konto";
  const alternateUrl = isRegistration ? root.dataset.loginUrl : root.dataset.registerUrl;
  const nonFieldError = errorMessages("__all__");

  return (
    <main className="page">
      <section className="card" aria-labelledby="auth-title">
        <h1 id="auth-title">{title}</h1>
        <p className="subtitle">Zarządzaj swoim kontem bezpiecznie.</p>
        <form method="post" action={root.dataset.action}>
          <input type="hidden" name="csrfmiddlewaretoken" value={csrfToken} />
          {nonFieldError && <p className="error form-error" role="alert">{nonFieldError}</p>}
          <Field
            id="username"
            label="Nazwa użytkownika"
            type="text"
            autoComplete="username"
            error={errorMessages("username")}
          />
          <Field
            id="password"
            label="Hasło"
            type="password"
            autoComplete={isRegistration ? "new-password" : "current-password"}
            error={errorMessages("password")}
          />
          <button className="button" type="submit">{submitText}</button>
        </form>
        <p className="alternate">{alternateText} <a href={alternateUrl}>{alternateLinkText}</a></p>
      </section>
    </main>
  );
}

createRoot(root).render(<AuthPage />);
